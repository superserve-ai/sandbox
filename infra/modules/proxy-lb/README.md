# proxy-lb

Terraform skeleton for the sandbox/staging proxy load balancer chain.

Existing inventory to model later includes:

- `sandbox-proxy-http-fwd`
- `sandbox-proxy-https-fwd`
- `sandbox-proxy-https-fwd-test`
- `sandbox-proxy-tcp`
- `sandbox-proxy-ssl`
- `sandbox-proxy-backend*`
- `sandbox-proxy-ig`
- `sandbox-proxy-hc`
- `sandbox-proxy-redirect-hc`

Generation callers additionally create zonal `GCE_VM_IP_PORT` NEGs and
resolver-aware `USE_SERVING_PORT` backend services. The owning environment
state adopts the existing URL maps, target proxies, and forwarding rules and
switches only their backend references; endpoint membership remains owned by
the rollout controller. Each route in the environment's rollout manifest
records both the applied backend references and the bounded adopted frontend
resource identities, so its migration prerequisite cannot be satisfied by a
standalone caller flag or detached backend names.
