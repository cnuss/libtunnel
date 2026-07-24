package v1alpha1

import (
	"context"
	"net"
	"net/http"
	"sync"

	v1 "github.com/cnuss/libtunnel/v1"
)

type interceptCtxImpl[T v1.Spec] struct {
	context.Context
	backend Engine[T]
	w       http.ResponseWriter
	r       *http.Request

	handler   http.HandlerFunc
	handlerMu sync.Mutex
}

// NewInterceptCtx builds the per-request InterceptCtx handed to interceptors.
// It embeds the request context (so the value satisfies context.Context) and
// seeds the default handler to proxy the request to the origin — the behavior
// when no interceptor matches or an interceptor declines by not replacing it.
func NewInterceptCtx[T v1.Spec](backend Engine[T], w http.ResponseWriter, r *http.Request) v1.InterceptCtx {
	i := &interceptCtxImpl[T]{
		Context: r.Context(),
		backend: backend,
		w:       w,
		r:       r,
	}
	i.handler = func(w http.ResponseWriter, r *http.Request) {
		backend.Proxy().ServeHTTP(w, r)
	}
	return i
}

// Handler implements [v1.InterceptCtx].
func (i *interceptCtxImpl[T]) Handler() http.HandlerFunc {
	i.handlerMu.Lock()
	defer i.handlerMu.Unlock()
	return i.handler
}

// Reconnect implements [v1.InterceptCtx].
func (i *interceptCtxImpl[T]) Reconnect(ctx context.Context) error {
	return i.backend.Reconnect(ctx)
}

// Target implements [v1.InterceptCtx].
func (i *interceptCtxImpl[T]) Target() net.Listener {
	return i.backend.Listener()
}

// WithHandler implements [v1.InterceptCtx].
func (i *interceptCtxImpl[T]) WithHandler(h http.HandlerFunc) v1.InterceptCtx {
	i.handlerMu.Lock()
	defer i.handlerMu.Unlock()
	i.handler = h
	return i
}

func (i *interceptCtxImpl[T]) Writer() http.ResponseWriter {
	return i.w
}

func (i *interceptCtxImpl[T]) Request() *http.Request {
	return i.r
}

var _ v1.InterceptCtx = (*interceptCtxImpl[v1.Spec])(nil)
var _ context.Context = (*interceptCtxImpl[v1.Spec])(nil)
