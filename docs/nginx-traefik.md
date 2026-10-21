# NGINX and Traefik (forward-auth)

Ailuros serves HTTP forward-auth on `AILUROS_FORWARDAUTH_ADDR` (`:9002`) for
NGINX `auth_request` and Traefik `ForwardAuth`. Point the proxy at
`http://ailuros:9002/`; `deploy/nginx/nginx.conf` and
`deploy/traefik/dynamic.yml` are working examples. Forward-auth never sees
request bodies, so it always inspects in `lite` mode. Ailuros answers 200 to
allow, 403 to block and 503 to fail closed. A request with more than one
`content-type` header, or a method that is not an HTTP token, is blocked as
malformed, also with 403, because `auth_request` passes no other denial
status through.

**What forward-auth sees.** The request line, headers and the URL query, so
Ailuros measures a GraphQL query in the URL (`query=`, on any method) and the smuggling flags that
need only headers (the shipped NGINX config clears `Content-Length` on the
auth subrequest, so `te_with_cl` and `multiple_content_length` mostly cannot
fire). It does not see bodies, so POSTed GraphQL is not measured. NGINX and
Traefik drop `Upgrade` and `Connection` from the auth request, so WebSocket
handshakes are not detected. There is no protocol (so no `te_on_h2`) and no
JA4: a client header carrying either could be forged. See
[Request signals and limits](signals.md).

## NGINX Gateway Fabric: every request, next to tinyauth

`auth_request` allows one check per location, so on a route that already
uses it for an auth service such as tinyauth, Ailuros only sees the requests
that reach that service's auth flow. Nesting the Ailuros check inside the auth
service's location does not help: NGINX skips access-phase handlers in
subrequests.

For [NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric),
the [Ailuros NGINX module](https://github.com/0x4272616E646F6E/ailuros-nginx-module)
closes that gap. It is a dynamic module, loaded into NGF's stock NGINX image
from a ConfigMap, that asks Ailuros about every request on the routes it is
attached to, before `auth_request` runs. It calls this same forward-auth
endpoint on `:9002`, so Ailuros needs no extra configuration. Releases,
supported NGF versions and the install manifests are in that repository.

How the module applies Ailuros's answer differs from `auth_request`:

- 403 (block, including malformed requests) reaches the client as 403, and
  Ailuros's own 503 (fail closed) as 503.
- Any other answer, such as the 500 for a misconfigured proxy, and an
  unreachable Ailuros are "no decision". The module's
  `ailuros_request_unavailable` setting then fails closed (503, the default)
  or lets the request through with a warning in NGINX's error log.
- The module also passes 400 and 413 through, though forward-auth does not
  currently send them.

The module only sends headers, so forward-auth's limits above apply to it
too. The proxy hygiene rules below apply to its `/_ailuros` location as
well.

## When Ailuros itself is unreachable

`AILUROS_FAILURE_MODE` only governs model failures. If Ailuros is down or
unreachable, the proxy decides what happens:

- NGINX: the example fails closed (503): after about 1.5 s when Ailuros
  hangs (1 s connect / 1.5 s read timeouts), and after about 1 s when its
  resolver is unreachable (`resolver_timeout 1s`).
  `deploy/nginx/nginx.conf` has a commented fail-open variant. It still
  enforces Ailuros's own 503 decisions (routes with `failure_mode: closed`),
  but `error_page 500` also catches any other 5xx from Ailuros (such as a 500
  for a misconfigured proxy), so the fail-open variant allows those requests.
  The example re-resolves `ailuros` at request time through a `resolver` line
  set to Docker's embedded DNS (`127.0.0.11`), so a restarted Ailuros is
  picked up within about 10 s (`valid=10s`) without an NGINX reload. Change
  that address to your environment's DNS server (on Kubernetes, the cluster
  DNS service IP). NGINX's resolver ignores `/etc/hosts` and the search
  domains in `resolv.conf`, so outside Docker set `$ailuros_upstream` to a
  fully qualified name (on Kubernetes,
  `ailuros.<namespace>.svc.cluster.local:9002`); if Ailuros has a fixed
  address, a literal `IP:port` there needs no resolver at all. A wrong
  resolver or name makes every auth subrequest fail: the shipped example then
  fails every request closed (503), but the fail-open variant lets every
  request through with **no inspection**. The `backend` upstream is still
  resolved once at startup.
- Traefik: ForwardAuth fails closed (500) when the auth service is unreachable. It
  has no built-in fail-open, so run Ailuros with replicas and readiness checks
  (`/readyz`) to keep it available.

## Client IP

Behind NGINX or Traefik, Ailuros determines the client address as follows:

1. `X-Real-IP`, but only on the NGINX header set: `X-Original-URI` present and
   `X-Forwarded-URI` absent. The NGINX example sets it from `$remote_addr`.
2. Otherwise, the last `X-Forwarded-For` hop.
3. Otherwise, the TCP peer address.

Values that are not valid IPs are skipped.

## Proxy hygiene

Proxies pass client headers through to the auth request, so the proxy in
front of Ailuros must set or overwrite every header Ailuros trusts:

- The original-request header set. Ailuros accepts exactly one: Traefik's
  `X-Forwarded-Method`/`X-Forwarded-Uri` or NGINX's
  `X-Original-Method`/`X-Original-URI`. A request carrying both
  `X-Forwarded-Uri` and `X-Original-URI` is rejected with 500, since one set
  was forged or the proxy is misconfigured. The NGINX example clears the
  Traefik headers for this reason.
- `X-Forwarded-Host` (or `Host`), which route matching uses.
- The client IP headers above.

Clients must not be able to reach Ailuros directly; otherwise they can forge
all of these.
