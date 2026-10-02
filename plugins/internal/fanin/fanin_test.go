package fanin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestForwardCopiesChangesThenStopsAtFirstError(t *testing.T) {
	changes := make(chan int)
	errs := make(chan error)
	output := make(chan int)
	outputErrors := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		Forward(context.Background(), changes, errs, output, outputErrors)
		close(done)
	}()

	for _, want := range []int{1, 2} {
		changes <- want
		if got := <-output; got != want {
			t.Fatalf("forwarded change = %d, want %d", got, want)
		}
	}
	close(changes)
	failure := errors.New("decode failed")
	errs <- nil
	errs <- failure
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Forward did not return after an error")
	}
	if got := <-outputErrors; !errors.Is(got, failure) {
		t.Fatalf("forwarded error = %v, want %v", got, failure)
	}
}

func TestForwardReturnsWhenContextEndsWithBlockedOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan int, 1)
	changes <- 1
	done := make(chan struct{})
	go func() {
		Forward(ctx, changes, make(chan error), make(chan int), make(chan error))
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Forward did not return after cancellation")
	}
}
