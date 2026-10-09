package scenariocontract

import "errors"

type Completion struct {
	Request       Request
	RequestSHA256 string
	Result        Result
}

// ValidateHistory refuses missing, substituted or unretired predecessors.
// The controller must read the actual protected request/result records first.
func ValidateHistory(current Request, history []Completion) error {
	if e := current.Validate(); e != nil {
		return e
	}
	if len(history) != current.Sequence-1 {
		return errors.New("every previous sequence must have an actual retirement result")
	}
	for i, c := range history {
		if c.Request.AttemptID != current.AttemptID || c.Request.Sequence != i+1 || c.Request.Pins != current.Pins {
			return errors.New("predecessor sequence or immutable pins differ")
		}
		if e := c.Result.Validate(c.Request, c.RequestSHA256); e != nil {
			return e
		}
		if i > 0 && c.Result.StartedAt.Before(history[i-1].Result.FinishedAt) {
			return errors.New("predecessor operations overlap")
		}
	}
	return nil
}
