package gogs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-playground/webhooks/v6/webhook"
	client "github.com/gogits/go-gogs-client"
)

// Gogs hook types
const (
	CreateEvent       webhook.Event = "create"
	DeleteEvent       webhook.Event = "delete"
	ForkEvent         webhook.Event = "fork"
	PushEvent         webhook.Event = "push"
	IssuesEvent       webhook.Event = "issues"
	IssueCommentEvent webhook.Event = "issue_comment"
	PullRequestEvent  webhook.Event = "pull_request"
	ReleaseEvent      webhook.Event = "release"
)

// Options is a namespace var for configuration options
var Options = WebhookOptions{}

// WebhookOptions is a namespace for configuration option methods
type WebhookOptions struct{}

// Webhook instance contains all methods needed to process events
type Webhook struct {
	token string
}

// Option is a configuration option for the webhook
type Option func(*Webhook) error

// Secret registers the BitBucket secret
func (WebhookOptions) Secret(secret string) Option {
	return func(hook *Webhook) error {
		hook.token = secret
		return nil
	}
}

// New creates and returns a WebHook instance denoted by the Provider type
func New(options ...Option) (*Webhook, error) {
	hook := new(Webhook)
	for _, opt := range options {
		if err := opt(hook); err != nil {
			return nil, fmt.Errorf("applying Option failed: %s", err)
		}
	}
	return hook, nil
}

func (hook Webhook) Parse(r *http.Request, events ...webhook.Event) (interface{}, error) {
	if len(events) == 0 {
		return nil, webhook.ErrEventNotSpecifiedToParse
	}
	if r.Method != http.MethodPost {
		return nil, webhook.ErrInvalidHTTPMethod
	}

	event := r.Header.Get("X-Gogs-Event")
	if event == "" {
		return nil, webhook.ErrMissingEventKeyHeader
	}

	gogsEvent := webhook.Event(event)
	if !gogsEvent.In(events) {
		return nil, webhook.ErrEventNotFound
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if err = hook.VerifyToken(r.Header.Get("X-Gogs-Signature"), body); err != nil {
		return nil, err
	}

	return hook.ParseBytes(body, gogsEvent)
}

func (hook Webhook) VerifyToken(signature string, b []byte) error {
	if signature == "" {
		return webhook.ErrTokenEmpty
	}

	mac := hmac.New(sha256.New, []byte(hook.token))
	_, _ = mac.Write(b)

	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(signature), []byte(expectedMAC)) {
		return nil
	}

	return webhook.ErrHMACVerificationFailed
}

// ParseBytes verifies and parses the events specified and returns the payload object or an error
func (Webhook) ParseBytes(b []byte, event webhook.Event) (interface{}, error) {
	switch event {
	case CreateEvent:
		var pl client.CreatePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ReleaseEvent:
		var pl client.ReleasePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PushEvent:
		var pl client.PushPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case DeleteEvent:
		var pl client.DeletePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ForkEvent:
		var pl client.ForkPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssuesEvent:
		var pl client.IssuesPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssueCommentEvent:
		var pl client.IssueCommentPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestEvent:
		var pl client.PullRequestPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	default:
		return nil, fmt.Errorf("unknown event %s", event)
	}
}
