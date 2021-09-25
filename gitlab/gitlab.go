package gitlab

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-playground/webhooks/v6/webhook"
)

// GitLab hook types
const (
	PushEvents               webhook.Event = "Push Hook"
	TagEvents                webhook.Event = "Tag Push Hook"
	IssuesEvents             webhook.Event = "Issue Hook"
	ConfidentialIssuesEvents webhook.Event = "Confidential Issue Hook"
	CommentEvents            webhook.Event = "Note Hook"
	MergeRequestEvents       webhook.Event = "Merge Request Hook"
	WikiPageEvents           webhook.Event = "Wiki Page Hook"
	PipelineEvents           webhook.Event = "Pipeline Hook"
	BuildEvents              webhook.Event = "Build Hook"
	JobEvents                webhook.Event = "Job Hook"
	SystemHookEvents         webhook.Event = "System Hook"

	objectPush         string = "push"
	objectTag          string = "tag_push"
	objectMergeRequest string = "merge_request"
	objectBuild        string = "build"
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

// Secret registers the GitLab secret
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

	if err := hook.VerifyToken(r.Header.Get("X-Gitlab-Token"), nil); err != nil {
		return nil, err
	}

	event := r.Header.Get("X-Gitlab-Event")
	if event == "" {
		return nil, webhook.ErrMissingEventKeyHeader
	}

	gitLabEvent := webhook.Event(event)
	if !gitLabEvent.In(events) {
		return nil, webhook.ErrEventNotFound
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	return hook.ParseBytes(body, gitLabEvent)
}

func (hook Webhook) VerifyToken(signature string, _ []byte) error {
	if hook.token != "" && signature == "" {
		return webhook.ErrTokenEmpty
	}

	if signature == hook.token {
		return nil
	}

	return webhook.ErrUUIDVerificationFailed
}

// ParseBytes verifies and parses the events specified and returns the payload object or an error
func (hook Webhook) ParseBytes(b []byte, event webhook.Event) (interface{}, error) {
	switch event {
	case PushEvents:
		var pl PushEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case TagEvents:
		var pl TagEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ConfidentialIssuesEvents:
		var pl ConfidentialIssueEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssuesEvents:
		var pl IssueEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case CommentEvents:
		var pl CommentEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case MergeRequestEvents:
		var pl MergeRequestEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case WikiPageEvents:
		var pl WikiPageEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PipelineEvents:
		var pl PipelineEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case BuildEvents:
		var pl BuildEventPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case JobEvents:
		var pl JobEventPayload
		err := json.Unmarshal(b, &pl)
		if err != nil {
			return nil, fmt.Errorf("error parsing payload: %s", err)
		}

		if pl.ObjectKind == objectBuild {
			return hook.ParseBytes(b, BuildEvents)
		}

		return pl, nil
	case SystemHookEvents:
		var pl SystemHookPayload
		err := json.Unmarshal(b, &pl)
		if err != nil {
			return nil, fmt.Errorf("error parsing payload: %s", err)
		}
		switch pl.ObjectKind {
		case objectPush:
			return hook.ParseBytes(b, PushEvents)
		case objectTag:
			return hook.ParseBytes(b, TagEvents)
		case objectMergeRequest:
			return hook.ParseBytes(b, MergeRequestEvents)
		default:
			switch pl.EventName {
			case objectPush:
				return hook.ParseBytes(b, PushEvents)
			case objectTag:
				return hook.ParseBytes(b, TagEvents)
			case objectMergeRequest:
				return hook.ParseBytes(b, MergeRequestEvents)
			default:
				return nil, fmt.Errorf("unknown system hook event %s", event)
			}
		}
	default:
		return nil, fmt.Errorf("unknown event %s", event)
	}
}
