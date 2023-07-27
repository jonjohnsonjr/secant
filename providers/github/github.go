package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	requestTokenEnvKey = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	requestURLEnvKey   = "ACTIONS_ID_TOKEN_REQUEST_URL"
)

type githubActions struct{}

// Enabled implements providers.Interface
func (ga *githubActions) Enabled(_ context.Context) bool {
	if os.Getenv(requestTokenEnvKey) == "" {
		return false
	}
	if os.Getenv(requestURLEnvKey) == "" {
		return false
	}
	return true
}

// Provide implements providers.Interface
func (ga *githubActions) Provide(ctx context.Context, audience string) (string, error) {
	url := os.Getenv(requestURLEnvKey) + "&audience=" + audience

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	// Retry up to 3 times.
	for i := 0; ; i++ {
		req.Header.Add("Authorization", "bearer "+os.Getenv(requestTokenEnvKey))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if i == 2 {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "error fetching GitHub OIDC token (will retry): %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		defer resp.Body.Close()

		var payload struct {
			Value string `json:"value"`
		}
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&payload); err != nil {
			return "", err
		}
		return payload.Value, nil
	}
}

func NewProvider() (*githubActions, error) {
	if os.Getenv(requestTokenEnvKey) == "" {
		return nil, fmt.Errorf("missing env %q", requestTokenEnvKey)
	}
	if os.Getenv(requestURLEnvKey) == "" {
		return nil, fmt.Errorf("missing env %q", requestURLEnvKey)
	}
	return &githubActions{}, nil
}
