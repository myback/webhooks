package bitbucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-playground/webhooks/v6/webhook"
)

var (
	ErrUUIDVerificationFailed = errors.New("UUID verification failed")
)

// Webhook instance contains all methods needed to process events
type Webhook struct {
	uuid string
}

// Bitbucket hook types
const (
	RepoPushEvent                  webhook.Event = "repo:push"
	RepoForkEvent                  webhook.Event = "repo:fork"
	RepoUpdatedEvent               webhook.Event = "repo:updated"
	RepoCommitCommentCreatedEvent  webhook.Event = "repo:commit_comment_created"
	RepoCommitStatusCreatedEvent   webhook.Event = "repo:commit_status_created"
	RepoCommitStatusUpdatedEvent   webhook.Event = "repo:commit_status_updated"
	IssueCreatedEvent              webhook.Event = "issue:created"
	IssueUpdatedEvent              webhook.Event = "issue:updated"
	IssueCommentCreatedEvent       webhook.Event = "issue:comment_created"
	PullRequestCreatedEvent        webhook.Event = "pullrequest:created"
	PullRequestUpdatedEvent        webhook.Event = "pullrequest:updated"
	PullRequestApprovedEvent       webhook.Event = "pullrequest:approved"
	PullRequestUnapprovedEvent     webhook.Event = "pullrequest:unapproved"
	PullRequestMergedEvent         webhook.Event = "pullrequest:fulfilled"
	PullRequestDeclinedEvent       webhook.Event = "pullrequest:rejected"
	PullRequestCommentCreatedEvent webhook.Event = "pullrequest:comment_created"
	PullRequestCommentUpdatedEvent webhook.Event = "pullrequest:comment_updated"
	PullRequestCommentDeletedEvent webhook.Event = "pullrequest:comment_deleted"
)

// Option is a configuration option for the webhook
type Option func(*Webhook) error

// Options is a namespace var for configuration options
var Options = WebhookOptions{}

// WebhookOptions is a namespace for configuration option methods
type WebhookOptions struct{}

// Secret registers the BitBucket secret
func (WebhookOptions) Secret(secret string) Option {
	return func(hook *Webhook) error {
		hook.uuid = secret
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

	if err := hook.VerifyToken(r.Header.Get("X-Hook-UUID"), nil); err != nil {
		return nil, err
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

	return hook.ParseBytes(body, bitbucketEvent)
}

func (hook Webhook) VerifyToken(uuid string, _ []byte) error {
	if uuid == "" {
		return webhook.ErrTokenEmpty
	}

	if hook.uuid == uuid {
		return nil
	}

	return ErrUUIDVerificationFailed
}

// ParseBytes verifies and parses the events specified and returns the payload object or an error
func (Webhook) ParseBytes(b []byte, event webhook.Event) (interface{}, error) {
	switch event {
	case RepoPushEvent:
		var pl RepoPushPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepoForkEvent:
		var pl RepoForkPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepoUpdatedEvent:
		var pl RepoUpdatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepoCommitCommentCreatedEvent:
		var pl RepoCommitCommentCreatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepoCommitStatusCreatedEvent:
		var pl RepoCommitStatusCreatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepoCommitStatusUpdatedEvent:
		var pl RepoCommitStatusUpdatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssueCreatedEvent:
		var pl IssueCreatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssueUpdatedEvent:
		var pl IssueUpdatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssueCommentCreatedEvent:
		var pl IssueCommentCreatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestCreatedEvent:
		var pl PullRequestCreatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestUpdatedEvent:
		var pl PullRequestUpdatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestApprovedEvent:
		var pl PullRequestApprovedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestUnapprovedEvent:
		var pl PullRequestUnapprovedPayload
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
	case PullRequestCommentCreatedEvent:
		var pl PullRequestCommentCreatedPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestCommentUpdatedEvent:
		var pl PullRequestCommentUpdatedPayload
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
