package main

import (
	"encoding/json"
	"fmt"
	"github.com/myback/webhooks/v6/github"
	"github.com/myback/webhooks/v6/gitlab"
	"github.com/myback/webhooks/v6/gogs"
	"github.com/myback/webhooks/v6/webhook"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	path = "/webhooks"
)

func main() {
	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		hookName := strings.TrimPrefix(r.RequestURI, path)
		hookName = strings.Replace(hookName, "/", "-", -1)

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		token := "abc"
		var wh webhook.Webhook
		var event webhook.Event
		var tokenHeaderKey string
		if ev := r.Header.Get("X-GitHub-Event"); ev != "" {
			wh, err = github.New(github.Options.Secret(token))
			if err != nil {
				fmt.Println("github: ", err)
				w.WriteHeader(500)
				return
			}

			tokenHeaderKey = "X-Hub-Signature"
			event = webhook.Event(ev)
		}

		if ev := r.Header.Get("X-Gitlab-Event"); ev != "" {
			wh, err = gitlab.New(gitlab.Options.Secret(token))
			if err != nil {
				fmt.Println("gitlab: ", err)
				w.WriteHeader(500)
				return
			}

			tokenHeaderKey = "X-Gitlab-Token"
			event = webhook.Event(ev)
		}

		if ev := r.Header.Get("X-Gogs-Event"); ev != "" {
			wh, err = gogs.New(gogs.Options.Secret(token))
			if err != nil {
				fmt.Println("gogs: ", err)
				w.WriteHeader(500)
				return
			}

			tokenHeaderKey = "X-Gogs-Signature"
			event = webhook.Event(ev)
		}

		if wh == nil || event == "" {
			fmt.Println(webhook.ErrMissingEventKeyHeader)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if err = wh.VerifyToken(r.Header.Get(tokenHeaderKey), body); err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		eventPayload, err := wh.ParseBytes(body, event)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		j, err := json.Marshal(eventPayload)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(string(j))
	})
	http.ListenAndServe(":3000", nil)
}
