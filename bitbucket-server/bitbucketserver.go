package bitbucketserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/myback/webhooks/v6/webhook"
)

const (
	RepositoryReferenceChangedEvent webhook.Event = "repo:refs_changed"
	RepositoryModifiedEvent         webhook.Event = "repo:modified"
	RepositoryForkedEvent           webhook.Event = "repo:forked"
	RepositoryCommentAddedEvent     webhook.Event = "repo:comment:added"
	RepositoryCommentEditedEvent    webhook.Event = "repo:comment:edited"
	RepositoryCommentDeletedEvent   webhook.Event = "repo:comment:deleted"

	PullRequestOpenedEvent               webhook.Event = "pr:opened"
	PullRequestFromReferenceUpdatedEvent webhook.Event = "pr:from_ref_updated"
	PullRequestModifiedEvent             webhook.Event = "pr:modified"
	PullRequestMergedEvent               webhook.Event = "pr:merged"
	PullRequestDeclinedEvent             webhook.Event = "pr:declined"
	PullRequestDeletedEvent              webhook.Event = "pr:deleted"

	PullRequestReviewerUpdatedEvent    webhook.Event = "pr:reviewer:updated"
	PullRequestReviewerApprovedEvent   webhook.Event = "pr:reviewer:approved"
	PullRequestReviewerUnapprovedEvent webhook.Event = "pr:reviewer:unapproved"
	PullRequestReviewerNeedsWorkEvent  webhook.Event = "pr:reviewer:needs_work"

	PullRequestCommentAddedEvent   webhook.Event = "pr:comment:added"
	PullRequestCommentEditedEvent  webhook.Event = "pr:comment:edited"
	PullRequestCommentDeletedEvent webhook.Event = "pr:comment:deleted"

	DiagnosticsPingEvent webhook.Event = "diagnostics:ping"
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

	event := r.Header.Get("X-Event-Key")
	if event == "" {
		return nil, webhook.ErrMissingEventKeyHeader
	}

	bitbucketEvent := webhook.Event(event)
	if !bitbucketEvent.In(events) {
		return nil, webhook.ErrEventNotFound
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if err = hook.VerifyToken(r.Header.Get("X-Hub-Signature"), body); err != nil {
		return nil, err
	}

	return hook.ParseBytes(body, bitbucketEvent)
}

func (hook Webhook) VerifyToken(signature string, b []byte) error {
	if signature == "" {
		return webhook.ErrTokenEmpty
	}

	mac := hmac.New(sha256.New, []byte(hook.token))
	_, _ = mac.Write(b)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(signature[7:]), []byte(expectedMAC)) {
		return nil
	}

	return webhook.ErrUUIDVerificationFailed
}

// ParseBytes verifies and parses the events specified and returns the payload object or an error
func (Webhook) ParseBytes(b []byte, event webhook.Event) (interface{}, error) {
	switch event {
	case DiagnosticsPingEvent:
		return DiagnosticsPingPayload{}, nil
	case RepositoryReferenceChangedEvent:
		var pl RepositoryReferenceChangedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryModifiedEvent:
		var pl RepositoryModifiedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryForkedEvent:
		var pl RepositoryForkedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryCommentAddedEvent:
		var pl RepositoryCommentAddedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryCommentEditedEvent:
		var pl RepositoryCommentEditedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryCommentDeletedEvent:
		var pl RepositoryCommentDeletedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestOpenedEvent:
		var pl PullRequestOpenedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestFromReferenceUpdatedEvent:
		var pl PullRequestFromReferenceUpdatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestModifiedEvent:
		var pl PullRequestModifiedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestMergedEvent:
		var pl PullRequestMergedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestDeclinedEvent:
		var pl PullRequestDeclinedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestDeletedEvent:
		var pl PullRequestDeletedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestReviewerUpdatedEvent:
		var pl PullRequestReviewerUpdatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestReviewerApprovedEvent:
		var pl PullRequestReviewerApprovedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestReviewerUnapprovedEvent:
		var pl PullRequestReviewerUnapprovedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestReviewerNeedsWorkEvent:
		var pl PullRequestReviewerNeedsWorkPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestCommentAddedEvent:
		var pl PullRequestCommentAddedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestCommentEditedEvent:
		var pl PullRequestCommentEditedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestCommentDeletedEvent:
		var pl PullRequestCommentDeletedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	default:
		return nil, fmt.Errorf("unknown event %s", event)
	}
}
