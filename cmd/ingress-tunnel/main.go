// Command ingress-tunnel is a proof-of-concept Kubernetes ingress controller
// backed by libtunnel: instead of an external load balancer, it watches
// networking.k8s.io Ingress objects and gives each one a Cloudflare quick
// tunnel, reverse-proxying public traffic into the backing Services by
// host/path. The minted https://<name>.trycloudflare.com hostname is written
// back to the Ingress's status, so `kubectl get ingress` shows the public URL.
//
// Run it as an in-cluster Deployment with a ServiceAccount allowed to watch
// Ingresses and patch their status (see README). It needs only egress to
// api.trycloudflare.com plus reachability to the backing Services — no inbound,
// no node ports, no cloud LB.
//
// Out of cluster, point -kubeconfig (or $KUBECONFIG) at a cluster for local
// development.
//
// Scope of the peek: HTTP only, numeric Service ports only, one tunnel per
// Ingress (each gets its own random hostname). TLS, named ports, and
// host-multiplexing over a single tunnel are future work.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	class := flag.String("ingress-class", env("INGRESS_CLASS", "tunnel"),
		"ingressClassName to manage; empty manages every Ingress (env INGRESS_CLASS)")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"),
		"path to a kubeconfig for out-of-cluster runs (env KUBECONFIG)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("ingress-tunnel: load kube config: %v", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("ingress-tunnel: build client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	factory := informers.NewSharedInformerFactory(client, 10*time.Minute)
	ingresses := factory.Networking().V1().Ingresses()
	ctrl := NewController(client, ingresses, *class, logger)

	factory.Start(ctx.Done())
	if err := ctrl.Run(ctx); err != nil {
		log.Fatalf("ingress-tunnel: %v", err)
	}
	logger.Info("stopped")
}

// loadConfig prefers the in-cluster service-account config and falls back to a
// kubeconfig file (flag/env, else the standard loading rules) for local runs.
func loadConfig(kubeconfig string) (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
