package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	netinformers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	netlisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cnuss/libtunnel"
)

// managedTunnel is one Ingress's live tunnel: a minted quick tunnel, an
// http.Server serving on it, and a hot-swappable router so rule changes apply
// without tearing the tunnel down (which would mint a new public hostname).
type managedTunnel struct {
	tun     libtunnel.TunneledV1
	srv     *http.Server
	handler atomic.Pointer[http.Handler]
	public  atomic.Pointer[string] // public host, set once the tunnel is ready
	stop    context.CancelFunc
}

// ServeHTTP routes through the current handler, or 503s until one is installed.
func (m *managedTunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := m.handler.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	http.Error(w, "ingress-tunnel: no route configured", http.StatusServiceUnavailable)
}

// Controller reconciles networking.k8s.io Ingress objects of a given class into
// libtunnel quick tunnels: one tunnel per Ingress, its rules compiled to a
// reverse-proxy router, the public hostname written back to Ingress status.
type Controller struct {
	client  kubernetes.Interface
	lister  netlisters.IngressLister
	synced  cache.InformerSynced
	queue   workqueue.TypedRateLimitingInterface[string]
	class   string
	log     *slog.Logger
	rootCtx context.Context

	mu      sync.Mutex
	tunnels map[string]*managedTunnel
}

// NewController wires the informer's events into a workqueue and returns a
// Controller ready to Run.
func NewController(client kubernetes.Interface, informer netinformers.IngressInformer, class string, log *slog.Logger) *Controller {
	c := &Controller{
		client:  client,
		lister:  informer.Lister(),
		synced:  informer.Informer().HasSynced,
		queue:   workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		class:   class,
		log:     log,
		tunnels: map[string]*managedTunnel{},
	}
	informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { c.enqueue(o) },
		UpdateFunc: func(_, o any) { c.enqueue(o) },
		DeleteFunc: func(o any) { c.enqueue(o) },
	})
	return c
}

func (c *Controller) enqueue(o any) {
	if key, err := cache.MetaNamespaceKeyFunc(o); err == nil {
		c.queue.Add(key)
	}
}

// Run syncs the cache, then processes the queue with a single worker until ctx
// is done, tearing every tunnel down on exit.
func (c *Controller) Run(ctx context.Context) error {
	defer c.queue.ShutDown()
	c.rootCtx = ctx

	c.log.Info("waiting for Ingress cache sync")
	if !cache.WaitForCacheSync(ctx.Done(), c.synced) {
		return errors.New("ingress cache sync failed")
	}
	c.log.Info("controller running", "class", c.class)
	go wait.UntilWithContext(ctx, c.worker, time.Second)

	<-ctx.Done()
	c.shutdownAll()
	return nil
}

func (c *Controller) worker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *Controller) processNext(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.reconcile(ctx, key); err != nil {
		c.log.Error("reconcile failed", "key", key, "error", err)
		c.queue.AddRateLimited(key)
		return true
	}
	c.queue.Forget(key)
	return true
}

// reconcile drives one Ingress toward its desired state: a managed tunnel with
// an up-to-date router when the Ingress is ours and routable, no tunnel
// otherwise, and the public hostname published to status once known.
func (c *Controller) reconcile(ctx context.Context, key string) error {
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	ing, err := c.lister.Ingresses(ns).Get(name)
	if apierrors.IsNotFound(err) {
		c.remove(key)
		return nil
	}
	if err != nil {
		return err
	}

	if !c.ours(ing) {
		c.remove(key) // class removed or never ours: drop any tunnel we had
		return nil
	}
	handler := buildHandler(ing)
	if handler == nil {
		c.log.Warn("ingress has no routable backend, skipping", "key", key)
		c.remove(key)
		return nil
	}

	mt := c.ensure(key)
	mt.handler.Store(&handler)

	if host := mt.public.Load(); host != nil {
		return c.publish(ctx, ing, *host)
	}
	return nil // public host not known yet; the URL watcher re-enqueues
}

// ensure returns the Ingress's managed tunnel, minting one on first call: it
// starts the edge connection, serves the router on it, and spawns a watcher
// that records the public host and re-enqueues to publish status.
func (c *Controller) ensure(key string) *managedTunnel {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mt, ok := c.tunnels[key]; ok {
		return mt
	}

	tctx, cancel := context.WithCancel(c.rootCtx)
	tun := libtunnel.New(libtunnel.Cloudflare()).WithLogger(c.log).WithContext(tctx)
	mt := &managedTunnel{tun: tun, stop: cancel}
	mt.srv = &http.Server{Handler: mt}
	c.tunnels[key] = mt

	lis := tun.Listener()
	if lis == nil {
		c.log.Error("listener mint failed", "key", key, "error", tun.Err())
		return mt
	}
	go func() {
		if err := mt.srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.log.Error("serve failed", "key", key, "error", err)
		}
	}()
	go func() {
		u := tun.URL()
		if u == nil {
			c.log.Error("tunnel never became ready", "key", key, "error", tun.Err())
			return
		}
		host := u.Host
		mt.public.Store(&host)
		c.log.Info("ingress tunnel live", "key", key, "public", u.String())
		c.queue.Add(key)
	}()
	return mt
}

// remove tears down and forgets the Ingress's tunnel, draining in-flight
// requests before cancelling the tunnel context.
func (c *Controller) remove(key string) {
	c.mu.Lock()
	mt := c.tunnels[key]
	delete(c.tunnels, key)
	c.mu.Unlock()
	if mt == nil {
		return
	}
	c.log.Info("removing ingress tunnel", "key", key)
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mt.srv.Shutdown(sctx) // drains, then closes the (minted) listener
	mt.stop()                 // cancels the tunnel context
}

func (c *Controller) shutdownAll() {
	c.mu.Lock()
	keys := make([]string, 0, len(c.tunnels))
	for k := range c.tunnels {
		keys = append(keys, k)
	}
	c.mu.Unlock()
	for _, k := range keys {
		c.remove(k)
	}
}

// ours reports whether the Ingress is one this controller manages: matched by
// spec.ingressClassName (or the legacy annotation), or any Ingress when the
// configured class is empty.
func (c *Controller) ours(ing *netv1.Ingress) bool {
	if c.class == "" {
		return true
	}
	if ing.Spec.IngressClassName != nil {
		return *ing.Spec.IngressClassName == c.class
	}
	return ing.Annotations["kubernetes.io/ingress.class"] == c.class
}

// publish writes host into the Ingress's status load-balancer list, a no-op
// once it is already present.
func (c *Controller) publish(ctx context.Context, ing *netv1.Ingress, host string) error {
	for _, lb := range ing.Status.LoadBalancer.Ingress {
		if lb.Hostname == host {
			return nil
		}
	}
	cp := ing.DeepCopy()
	cp.Status.LoadBalancer.Ingress = []netv1.IngressLoadBalancerIngress{{Hostname: host}}
	_, err := c.client.NetworkingV1().Ingresses(cp.Namespace).UpdateStatus(ctx, cp, metav1.UpdateOptions{})
	return err
}
