package webhook

type Event string

func (e Event) In(events []Event) bool {
	for _, evt := range events {
		if evt == e {
			return true
		}
	}

	return false
}
