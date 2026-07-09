# ingress-tunnel (proof-of-concept)

Can libtunnel back a Kubernetes ingress controller? This command watches
`networking.k8s.io` **Ingress** objects and gives each one a Cloudflare quick
tunnel, reverse-proxying public traffic into the backing Services by host/path.
The minted public hostname is written to the Ingress's status, so it shows up in
`kubectl get ingress`.

```
public internet ──▶ <name>.trycloudflare.com ──▶ ingress-tunnel pod ──▶ Service
```

No LoadBalancer, no Ingress-attached cloud LB, no node ports — the pod needs
only egress to `api.trycloudflare.com` and reachability to the Services.

## Module layout

This PoC is its **own Go module** (`cmd/ingress-tunnel/go.mod`) so the heavy
client-go dependency tree stays out of the libtunnel library module. It depends
on the local libtunnel via a `replace` directive, so it builds standalone:

```sh
cd cmd/ingress-tunnel && go build ./...
```

A root `go.work` (gitignored) wires both modules for a single IDE/workspace view
during development; the `replace` is what makes the committed module reproducible.

## Run it out-of-cluster (local dev)

Against any cluster your kubeconfig can reach:

```sh
cd cmd/ingress-tunnel
go run . -kubeconfig ~/.kube/config -ingress-class tunnel
```

Apply a Service + Ingress of class `tunnel`, and the controller mints a tunnel
and fills in the public hostname:

```sh
kubectl get ingress my-app -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
# impact-dont-anticipated-street.trycloudflare.com
```

## Run it in-cluster

Build/push an image whose entrypoint is this binary, then apply RBAC + a
Deployment. The controller needs to watch Ingresses and patch their status:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: ingress-tunnel, namespace: ingress-tunnel }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ingress-tunnel }
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses/status"]
    verbs: ["update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ingress-tunnel }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ingress-tunnel }
subjects:
  - { kind: ServiceAccount, name: ingress-tunnel, namespace: ingress-tunnel }
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: { name: tunnel }
spec: { controller: libtunnel.cnuss.github.io/ingress-tunnel }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: ingress-tunnel, namespace: ingress-tunnel }
spec:
  replicas: 1
  selector: { matchLabels: { app: ingress-tunnel } }
  template:
    metadata: { labels: { app: ingress-tunnel } }
    spec:
      serviceAccountName: ingress-tunnel
      containers:
        - name: ingress-tunnel
          image: <your-registry>/ingress-tunnel:latest
          args: ["-ingress-class", "tunnel"]
```

Then any Ingress of class `tunnel` is exposed:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: { name: my-app }
spec:
  ingressClassName: tunnel
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-app
                port: { number: 80 }
```

## Scope / next steps

- **HTTP only**, **numeric Service ports only** (named ports need a Service
  lookup), **one tunnel per Ingress** — each gets its own random hostname.
- Quick-tunnel traffic always arrives under the random `*.trycloudflare.com`
  host, so `host:` rules rarely fire; routing is effectively path-based.
- Future: TLS origins, named ports, multiplexing many hostnames over one tunnel,
  leader election for HA.

> **Status:** exploratory. Not wired into CI or releases; lives here only while
> we decide whether this belongs in libtunnel at all.
