package webhook

// Webhook instance contains all methods needed to process events
type Webhook interface {
	ParseBytes([]byte, Event) (interface{}, error)
	VerifyToken(string, []byte) error
}
