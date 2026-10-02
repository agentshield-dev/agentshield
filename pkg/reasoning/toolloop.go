package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// toolLoop is the one bounded model tool loop behind [Client.GenerateWithTools]
// and [Client.Investigate]. Each call is checked against limits before it
// runs and its result before it reaches the model, so a model cannot loop, fan
// out, or grow its own input without bound. A refused call is answered with
// the refusal, so the model can correct itself; only an error from next, run,
// or reply ends the run early.
type toolLoop struct {
	limits StructuredToolLimits
	// tools names every callable tool.
	tools map[string]struct{}
	// final names the tool that ends the run when it succeeds; it does not use
	// the call budget. Without one, the run ends at the first turn without a call.
	final string
	// next requests one model turn and returns its tool calls. last is true for
	// the final allowed turn, which must finish or answer.
	next func(ctx context.Context, last bool) ([]toolLoopCall, error)
	// run executes one admitted call. It returns the result, or a refusal for
	// the model; an error ends the run.
	run func(ctx context.Context, call toolLoopCall) (json.RawMessage, string, error)
	// reply returns a call's outcome to the model and records it.
	reply func(call toolLoopCall, outcome toolLoopOutcome) error
}

type toolLoopCall struct {
	ID        string
	Name      string
	Arguments []byte
}

// toolLoopOutcome is what happened to one call: an accepted Result, or a
// Refusal. Executed is false when the call was refused before it ran.
type toolLoopOutcome struct {
	Result   json.RawMessage
	Refusal  string
	Executed bool
}

// execute runs the loop until the final tool succeeds or, without a final
// tool, until the model answers without calling a tool.
func (loop toolLoop) execute(ctx context.Context) error {
	calls, resultBytes := 0, 0
	for turn := 0; turn < loop.limits.MaxTurns; turn++ {
		requested, err := loop.next(ctx, turn == loop.limits.MaxTurns-1)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			if loop.final != "" {
				return errors.New("model returned no tool call although one is required")
			}
			return nil
		}
		finished := false
		for _, call := range requested {
			final := loop.final != "" && call.Name == loop.final
			_, known := loop.tools[call.Name]
			var outcome toolLoopOutcome
			switch {
			case finished:
				outcome.Refusal = "not executed: the run already finished"
			case len(call.Arguments) > loop.limits.MaxArgumentBytes || !json.Valid(call.Arguments):
				outcome.Refusal = "tool arguments must be valid JSON within the configured byte limit"
			case !known:
				outcome.Refusal = "tool is not available"
			case !final && calls >= loop.limits.MaxCalls:
				outcome.Refusal = loop.budgetRefusal()
			default:
				if !final {
					calls++
				}
				outcome.Executed = true
				result, refusal, err := loop.run(ctx, call)
				if err != nil {
					return err
				}
				switch {
				case refusal != "":
					outcome.Refusal = refusal
				case !json.Valid(result):
					outcome.Refusal = "tool returned invalid JSON"
				case len(result) > loop.limits.MaxResultBytes:
					outcome.Refusal = "tool result exceeded the configured byte limit"
				case resultBytes+len(result) > loop.limits.MaxTotalResultBytes:
					outcome.Refusal = "total tool result budget exhausted"
				default:
					outcome.Result = append(json.RawMessage(nil), result...)
					resultBytes += len(result)
					finished = final
				}
			}
			if err := loop.reply(call, outcome); err != nil {
				return err
			}
		}
		if finished {
			return nil
		}
	}
	if loop.final != "" {
		return fmt.Errorf("model did not call %s within the turn limit", loop.final)
	}
	return errors.New("model did not answer within the turn limit")
}

func (loop toolLoop) budgetRefusal() string {
	if loop.final != "" {
		return fmt.Sprintf("tool call budget exhausted; call %s to finish", loop.final)
	}
	return "tool call budget exhausted; answer from the context already returned"
}

// validate checks limits against the given byte ceilings.
func (limits StructuredToolLimits) validate(maxArgumentBytes, maxResultBytes, maxTotalResultBytes int) error {
	if limits.MaxTurns < 1 || limits.MaxTurns > 32 || limits.MaxCalls < 0 || limits.MaxCalls > 32 ||
		limits.MaxArgumentBytes < 1 || limits.MaxArgumentBytes > maxArgumentBytes ||
		limits.MaxResultBytes < 1 || limits.MaxResultBytes > maxResultBytes ||
		limits.MaxTotalResultBytes < limits.MaxResultBytes || limits.MaxTotalResultBytes > maxTotalResultBytes {
		return errors.New("structured tool limits are invalid")
	}
	return nil
}
