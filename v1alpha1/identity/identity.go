package identity

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Identity struct {
	ctx    context.Context
	gh     string
	ghMu   sync.Mutex
	ghOnce sync.Once
	ghDone chan struct{}
}

func New() *Identity {
	ctx := context.Background()
	return &Identity{
		ctx:    ctx,
		gh:     "",
		ghMu:   sync.Mutex{},
		ghOnce: sync.Once{},
		ghDone: make(chan struct{}),
	}
}

func (i *Identity) Discover() {
	i.discoverGithub()
}

func (i *Identity) discoverGithub() {
	go func() {
		ctx, cancel := context.WithTimeout(i.ctx, 500*time.Millisecond)
		defer cancel()
		out, _ := exec.CommandContext(ctx, "gh", "auth", "token").Output()
		if token := strings.TrimSpace(string(out)); strings.HasPrefix(token, "gh") {
			i.emit("gh", token)
		}
	}()

	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN"} {
		go func() {
			if v := os.Getenv(env); v != "" {
				i.emit("gh", v)
			}
		}()
	}
}

// String returns the first GitHub token any discovery goroutine resolves,
// waiting up to 500ms. Empty string if none resolve in time.
func (i *Identity) String() string {
	select {
	case <-i.ghDone:
		i.ghMu.Lock()
		defer i.ghMu.Unlock()
		return i.gh
	case <-time.After(500 * time.Millisecond):
		return ""
	}
}

func (i *Identity) emit(provider, token string) {
	if provider == "gh" {
		i.ghOnce.Do(func() {
			i.ghMu.Lock()
			defer i.ghMu.Unlock()
			i.gh = token
			close(i.ghDone)
		})
	}
}
