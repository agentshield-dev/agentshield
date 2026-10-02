package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"
)

// subscriberBuffer is the live-change headroom per subscriber beyond the
// replayed items. A subscriber that falls further behind is switched to a
// coalesced backlog instead of being disconnected.
const subscriberBuffer = 1024

// lagLogInterval limits how often one subscriber's lag is logged.
const lagLogInterval = time.Minute

// collection holds the current state of one (source, collection) stream:
// the latest upsert per key, the last sync marker, and live subscribers.
type collection struct {
	items       map[string]Change
	subscribers map[uint64]*subscriber
	nextID      uint64
	sync        *Change
	// stale holds the keys present when the publishing plugin instance last
	// restarted and not republished since; see [Hub.beginResync].
	stale map[string]struct{}
}

// subscriber is one live subscription. Publish sends to channel directly while
// it has room. Once it is full, later changes go to backlog and a drain
// goroutine forwards them as the consumer catches up, so a slow consumer
// never blocks the publisher and never misses a delete.
type subscriber struct {
	pluginID string
	channel  chan Change
	done     <-chan struct{}
	// backlog is non-nil while a drain goroutine owns delivery.
	backlog *backlog
	// removed is set when the subscription ends. The channel is closed by the
	// cancellation goroutine when no drain is running, and otherwise by the
	// drain goroutine.
	removed   bool
	lagSince  time.Time
	lagLogged time.Time
	logged    bool
}

// backlog coalesces a lagging subscriber's pending changes to the latest
// change per key. Only the newest sync marker is kept: changes published
// before it are in before and later ones in after. Delivering before, the
// marker, and then after moves the subscriber's cache to the collection's
// state at that marker and then to its current state. Deletes are kept as
// changes, so a key removed while the subscriber lagged is still removed from
// its cache. A delete for a key the subscriber never saw is a no-op for it.
type backlog struct {
	before map[string]Change
	sync   *Change
	after  map[string]Change
}

func newBacklog() *backlog {
	return &backlog{before: make(map[string]Change), after: make(map[string]Change)}
}

func (b *backlog) add(change Change) {
	if change.Operation == OperationSync {
		if b.sync != nil {
			// A consumer only needs the newest coherent state, so an older
			// marker is dropped and the changes around it merge.
			maps.Copy(b.before, b.after)
			clear(b.after)
		}
		b.sync = &change
		return
	}
	if b.sync == nil {
		b.before[change.Key] = change
	} else {
		b.after[change.Key] = change
	}
}

func (b *backlog) empty() bool {
	return len(b.before) == 0 && b.sync == nil && len(b.after) == 0
}

// take returns the pending changes in delivery order and resets b.
func (b *backlog) take() []Change {
	result := make([]Change, 0, len(b.before)+len(b.after)+1)
	result = appendSorted(result, b.before)
	if b.sync != nil {
		result = append(result, *b.sync)
	}
	result = appendSorted(result, b.after)
	clear(b.before)
	clear(b.after)
	b.sync = nil
	return result
}

func appendSorted(result []Change, changes map[string]Change) []Change {
	for _, key := range slices.Sorted(maps.Keys(changes)) {
		result = append(result, changes[key])
	}
	return result
}

// Hub is the in-memory fan-out for observation collections. It keeps only
// current state, not history, and is safe for concurrent use. One mutex
// serializes Publish and the replay half of Subscribe, which is what makes
// replay-then-live ordering gap-free.
type Hub struct {
	mu          sync.Mutex
	collections map[collectionKey]*collection
	buffer      int
	logger      *slog.Logger
}

type collectionKey struct {
	sourceID   string
	collection string
}

// NewHub returns a hub with no collections. Each subscriber gets
// subscriberBuffer slots of live headroom, and the hub logs to slog.Default.
func NewHub() *Hub {
	return &Hub{collections: make(map[collectionKey]*collection), buffer: subscriberBuffer, logger: slog.Default()}
}

// Publish applies change to the collection's current state and delivers it to
// every live subscriber without blocking. A subscriber whose buffer is full
// receives the change later through its coalesced backlog; see [Hub.Subscribe].
func (h *Hub) Publish(ctx context.Context, change Change) error {
	if err := validateChange(change); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.publishLocked(change)
	return nil
}

// publishLocked applies a validated change and delivers it. h.mu must be held.
func (h *Hub) publishLocked(change Change) {
	key := collectionKey{sourceID: change.SourceID, collection: change.Collection}
	stream := h.collection(change.SourceID, change.Collection)
	switch change.Operation {
	case OperationUpsert:
		stream.items[change.Key] = change
		delete(stream.stale, change.Key)
	case OperationDelete:
		delete(stream.items, change.Key)
		delete(stream.stale, change.Key)
	case OperationSync:
		marker := change
		stream.sync = &marker
	}
	for _, sub := range stream.subscribers {
		if sub.backlog != nil {
			sub.backlog.add(change)
			continue
		}
		select {
		case sub.channel <- change:
		default:
			sub.backlog = newBacklog()
			sub.backlog.add(change)
			sub.lagSince = time.Now()
			sub.logged = sub.lagLogged.IsZero() || sub.lagSince.Sub(sub.lagLogged) >= lagLogInterval
			if sub.logged {
				sub.lagLogged = sub.lagSince
				h.logger.Warn("discovery subscriber is lagging; coalescing changes until it catches up",
					"source", key.sourceID, "collection", key.collection, "subscriber", sub.pluginID, "buffer", cap(sub.channel))
			}
			go h.drain(key, sub)
		}
	}
}

// beginResync marks every current item of the named collections as stale.
// The manager calls it before restarting the plugin instance that publishes
// them: the new instance rebuilds its cache from the provider and republishes
// what still exists, but it cannot publish deletes for objects that vanished
// while it was down. [Hub.staleItems] returns what it did not republish.
func (h *Hub) beginResync(sourceID string, names []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, name := range names {
		stream := h.collection(sourceID, name)
		if len(stream.items) == 0 {
			continue
		}
		stream.stale = make(map[string]struct{}, len(stream.items))
		for key := range stream.items {
			stream.stale[key] = struct{}{}
		}
	}
}

// staleItems returns, in key order, the items still marked stale.
func (h *Hub) staleItems(sourceID, name string) []Change {
	h.mu.Lock()
	defer h.mu.Unlock()
	stream := h.collections[collectionKey{sourceID: sourceID, collection: name}]
	if stream == nil || len(stream.stale) == 0 {
		return nil
	}
	result := make([]Change, 0, len(stream.stale))
	for _, key := range slices.Sorted(maps.Keys(stream.stale)) {
		result = append(result, stream.items[key])
	}
	return result
}

// deleteStale publishes change, a delete, only if its key is still stale, so
// a concurrent republish of the key wins over the sweep.
func (h *Hub) deleteStale(change Change) {
	h.mu.Lock()
	defer h.mu.Unlock()
	stream := h.collections[collectionKey{sourceID: change.SourceID, collection: change.Collection}]
	if stream == nil {
		return
	}
	if _, stale := stream.stale[change.Key]; !stale {
		return
	}
	h.publishLocked(change)
}

// endResync clears the collection's stale marks.
func (h *Hub) endResync(sourceID, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if stream := h.collections[collectionKey{sourceID: sourceID, collection: name}]; stream != nil {
		stream.stale = nil
	}
}

// drain forwards a lagging subscriber's backlog until it is empty, then
// hands delivery back to Publish. It never holds h.mu while sending.
func (h *Hub) drain(key collectionKey, sub *subscriber) {
	for {
		h.mu.Lock()
		if sub.removed {
			close(sub.channel)
			h.mu.Unlock()
			return
		}
		if sub.backlog.empty() {
			sub.backlog = nil
			if sub.logged {
				h.logger.Info("discovery subscriber caught up",
					"source", key.sourceID, "collection", key.collection, "subscriber", sub.pluginID,
					"lagged", time.Since(sub.lagSince).Round(time.Millisecond))
			}
			h.mu.Unlock()
			return
		}
		pending := sub.backlog.take()
		h.mu.Unlock()
		for _, change := range pending {
			select {
			case sub.channel <- change:
			case <-sub.done:
				h.mu.Lock()
				if sub.removed {
					close(sub.channel)
				} else {
					// The cancellation goroutine has not run yet; with no
					// drain in progress it closes the channel itself.
					sub.backlog = nil
				}
				h.mu.Unlock()
				return
			}
		}
	}
}

// Subscribe returns a channel that first replays the collection's current
// items in key order and its last sync marker, all marked Initial, and then
// carries live changes. Subscribing before the publisher starts is allowed;
// the replay is simply empty. The channel closes only when ctx ends.
//
// A subscriber that falls more than the live buffer behind is not
// disconnected. Its pending changes are coalesced to the latest change per key
// and the newest sync marker, and delivered as it catches up. It may skip
// intermediate versions of a key and older sync markers, as a fresh replay
// would, but every sync marker it receives is preceded by exactly the state
// the collection had when that marker was published, and its cache converges
// to the collection's current state, including deletes.
func (h *Hub) Subscribe(ctx context.Context, sourceID, name string) (<-chan Change, error) {
	return h.subscribe(ctx, sourceID, name, "")
}

// subscribe is Subscribe with the subscribing plugin's ID for lag logs.
func (h *Hub) subscribe(ctx context.Context, sourceID, name, pluginID string) (<-chan Change, error) {
	if sourceID == "" || name == "" {
		return nil, errors.New("source and collection names are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	key := collectionKey{sourceID: sourceID, collection: name}
	stream := h.collection(sourceID, name)
	// Size the buffer so the replay below never blocks while h.mu is held.
	capacity := h.buffer + len(stream.items) + 1
	channel := make(chan Change, capacity)
	// Replay the current collection deterministically before its saved sync marker;
	// later changes on the same channel are the live continuation of that state.
	keys := make([]string, 0, len(stream.items))
	for key := range stream.items {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		change := stream.items[key]
		change.Initial = true
		channel <- change
	}
	if stream.sync != nil {
		change := *stream.sync
		change.Initial = true
		channel <- change
	}
	id := stream.nextID
	stream.nextID++
	sub := &subscriber{pluginID: pluginID, channel: channel, done: ctx.Done()}
	stream.subscribers[id] = sub
	h.mu.Unlock()

	go func() {
		<-ctx.Done()
		h.mu.Lock()
		defer h.mu.Unlock()
		stream := h.collections[key]
		if stream == nil || stream.subscribers[id] != sub {
			return
		}
		delete(stream.subscribers, id)
		sub.removed = true
		if sub.backlog == nil {
			close(channel)
		}
	}()
	return channel, nil
}

func (h *Hub) collection(sourceID, name string) *collection {
	key := collectionKey{sourceID: sourceID, collection: name}
	stream := h.collections[key]
	if stream == nil {
		stream = &collection{items: make(map[string]Change), subscribers: make(map[uint64]*subscriber)}
		h.collections[key] = stream
	}
	return stream
}

func validateChange(change Change) error {
	if change.PluginID == "" || change.SourceID == "" || change.Collection == "" || change.Key == "" || change.Generation == 0 || change.Operation == "" {
		return errors.New("change requires plugin, source, collection, key, generation, and operation")
	}
	if change.Operation != OperationSync && change.EventID == "" {
		return errors.New("non-sync change requires an event ID")
	}
	if change.Operation == OperationUpsert && len(change.Payload) == 0 {
		return errors.New("upsert change requires a payload")
	}
	if change.Operation != OperationUpsert && change.Operation != OperationDelete && change.Operation != OperationSync {
		return fmt.Errorf("unsupported discovery operation %q", change.Operation)
	}
	return nil
}
