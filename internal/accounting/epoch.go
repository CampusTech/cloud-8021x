package accounting

import "time"

// ApplyEpoch never reconstructs traffic from before collection began. Ongoing
// sessions establish a zero-credit baseline; a new Start keeps the normal zero
// counter baseline. Rejected pre-epoch observations cannot stop or move a session.
func ApplyEpoch(s State, e Event, epoch time.Time) (State, *Interval, string) {
	if !epoch.IsZero() && e.Received.Before(epoch) {
		return s, nil, "before_collection_epoch"
	}
	return Apply(s, e)
}
