package docker

// this package receives the Docker Hub Automated Build webhook
// https://docs.docker.com/docker-hub/webhooks/
// NOT the Docker Trusted Registry webhook
// https://docs.docker.com/ee/dtr/user/create-and-manage-webhooks/

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrInvalidHTTPMethod = errors.New("invalid HTTP Method")
)

// Event defines a Docker hook event type
type Event string

// Docker hook types (only one for now)
const (
	BuildEvent Event = "build"
)

// BuildPayload a docker hub build notice
// https://docs.docker.com/docker-hub/webhooks/
type BuildPayload struct {
	CallbackURL string `json:"callback_url"`
	PushData    struct {
		Images   []string `json:"images"`
		PushedAt float32  `json:"pushed_at"`
		Pusher   string   `json:"pusher"`
		Tag      string   `json:"tag"`
	} `json:"push_data"`
	Repository struct {
		CommentCount    int     `json:"comment_count"`
		DateCreated     float32 `json:"date_created"`
		Description     string  `json:"description"`
		Dockerfile      string  `json:"dockerfile"`
		FullDescription string  `json:"full_description"`
		IsOfficial      bool    `json:"is_official"`
		IsPrivate       bool    `json:"is_private"`
		IsTrusted       bool    `json:"is_trusted"`
		Name            string  `json:"name"`
		Namespace       string  `json:"namespace"`
		Owner           string  `json:"owner"`
		RepoName        string  `json:"repo_name"`
		RepoURL         string  `json:"repo_url"`
		StarCount       int     `json:"star_count"`
		Status          string  `json:"status"`
	} `json:"repository"`
}

// Webhook instance contains all methods needed to process events
type Webhook struct {
}

// New creates and returns a WebHook instance
func New() (*Webhook, error) {
	hook := new(Webhook)
	return hook, nil
}

// Parse verifies and parses the events specified and returns the payload object or an error
func (hook Webhook) Parse(r *http.Request, events ...Event) (interface{}, error) {
	if r.Method != http.MethodPost {
		return nil, ErrInvalidHTTPMethod
	}

	var pl BuildPayload
	if err := json.NewDecoder(r.Body).Decode(&pl); err != nil {
		return nil, fmt.Errorf("error parsing payload: %s", err)
	}
	defer r.Body.Close()

	return pl, nil
}
