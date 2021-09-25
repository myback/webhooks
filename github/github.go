package github

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/myback/webhooks/v6/webhook"
)

// GitHub hook types
const (
	CheckRunEvent                            webhook.Event = "check_run"
	CheckSuiteEvent                          webhook.Event = "check_suite"
	CommitCommentEvent                       webhook.Event = "commit_comment"
	CreateEvent                              webhook.Event = "create"
	DeleteEvent                              webhook.Event = "delete"
	DeploymentEvent                          webhook.Event = "deployment"
	DeploymentStatusEvent                    webhook.Event = "deployment_status"
	ForkEvent                                webhook.Event = "fork"
	GollumEvent                              webhook.Event = "gollum"
	InstallationEvent                        webhook.Event = "installation"
	InstallationRepositoriesEvent            webhook.Event = "installation_repositories"
	IntegrationInstallationEvent             webhook.Event = "integration_installation"
	IntegrationInstallationRepositoriesEvent webhook.Event = "integration_installation_repositories"
	IssueCommentEvent                        webhook.Event = "issue_comment"
	IssuesEvent                              webhook.Event = "issues"
	LabelEvent                               webhook.Event = "label"
	MemberEvent                              webhook.Event = "member"
	MembershipEvent                          webhook.Event = "membership"
	MilestoneEvent                           webhook.Event = "milestone"
	MetaEvent                                webhook.Event = "meta"
	OrganizationEvent                        webhook.Event = "organization"
	OrgBlockEvent                            webhook.Event = "org_block"
	PageBuildEvent                           webhook.Event = "page_build"
	PingEvent                                webhook.Event = "ping"
	ProjectCardEvent                         webhook.Event = "project_card"
	ProjectColumnEvent                       webhook.Event = "project_column"
	ProjectEvent                             webhook.Event = "project"
	PublicEvent                              webhook.Event = "public"
	PullRequestEvent                         webhook.Event = "pull_request"
	PullRequestReviewEvent                   webhook.Event = "pull_request_review"
	PullRequestReviewCommentEvent            webhook.Event = "pull_request_review_comment"
	PushEvent                                webhook.Event = "push"
	ReleaseEvent                             webhook.Event = "release"
	RepositoryEvent                          webhook.Event = "repository"
	RepositoryVulnerabilityAlertEvent        webhook.Event = "repository_vulnerability_alert"
	SecurityAdvisoryEvent                    webhook.Event = "security_advisory"
	StatusEvent                              webhook.Event = "status"
	TeamEvent                                webhook.Event = "team"
	TeamAddEvent                             webhook.Event = "team_add"
	WatchEvent                               webhook.Event = "watch"
)

// EventSubtype defines a GitHub Hook Event subtype
type EventSubtype string

// GitHub hook event subtypes
const (
	NoSubtype     EventSubtype = ""
	BranchSubtype EventSubtype = "branch"
	TagSubtype    EventSubtype = "tag"
	PullSubtype   EventSubtype = "pull"
	IssueSubtype  EventSubtype = "issues"
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

// Secret registers the GitHub secret
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

	event := r.Header.Get("X-GitHub-Event")
	if event == "" {
		return nil, webhook.ErrMissingEventKeyHeader
	}

	gitHubEvent := webhook.Event(event)
	if !gitHubEvent.In(events) {
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

	return hook.ParseBytes(body, gitHubEvent)
}

func (hook Webhook) VerifyToken(signature string, b []byte) error {
	if hook.token != "" && signature == "" {
		return webhook.ErrTokenEmpty
	}

	mac := hmac.New(sha1.New, []byte(hook.token))
	_, _ = mac.Write(b)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(signature[5:]), []byte(expectedMAC)) {
		return nil
	}

	return webhook.ErrHMACVerificationFailed
}

// ParseBytes verifies and parses the events specified and returns the payload object or an error
func (Webhook) ParseBytes(b []byte, event webhook.Event) (interface{}, error) {
	switch event {
	case CheckRunEvent:
		var pl CheckRunPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case CheckSuiteEvent:
		var pl CheckSuitePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case CommitCommentEvent:
		var pl CommitCommentPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case CreateEvent:
		var pl CreatePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case DeleteEvent:
		var pl DeletePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case DeploymentEvent:
		var pl DeploymentPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case DeploymentStatusEvent:
		var pl DeploymentStatusPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ForkEvent:
		var pl ForkPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case GollumEvent:
		var pl GollumPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case InstallationEvent, IntegrationInstallationEvent:
		var pl InstallationPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case InstallationRepositoriesEvent, IntegrationInstallationRepositoriesEvent:
		var pl InstallationRepositoriesPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssueCommentEvent:
		var pl IssueCommentPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case IssuesEvent:
		var pl IssuesPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case LabelEvent:
		var pl LabelPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case MemberEvent:
		var pl MemberPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case MembershipEvent:
		var pl MembershipPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case MetaEvent:
		var pl MetaPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case MilestoneEvent:
		var pl MilestonePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case OrganizationEvent:
		var pl OrganizationPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case OrgBlockEvent:
		var pl OrgBlockPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PageBuildEvent:
		var pl PageBuildPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PingEvent:
		var pl PingPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ProjectCardEvent:
		var pl ProjectCardPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ProjectColumnEvent:
		var pl ProjectColumnPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ProjectEvent:
		var pl ProjectPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PublicEvent:
		var pl PublicPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestEvent:
		var pl PullRequestPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestReviewEvent:
		var pl PullRequestReviewPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PullRequestReviewCommentEvent:
		var pl PullRequestReviewCommentPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case PushEvent:
		var pl PushPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case ReleaseEvent:
		var pl ReleasePayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryEvent:
		var pl RepositoryPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case RepositoryVulnerabilityAlertEvent:
		var pl RepositoryVulnerabilityAlertPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case SecurityAdvisoryEvent:
		var pl SecurityAdvisoryPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case StatusEvent:
		var pl StatusPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case TeamEvent:
		var pl TeamPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case TeamAddEvent:
		var pl TeamAddPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	case WatchEvent:
		var pl WatchPayload
		err := json.Unmarshal(b, &pl)
		return pl, err
	default:
		return nil, fmt.Errorf("unknown event %s", event)
	}
}
