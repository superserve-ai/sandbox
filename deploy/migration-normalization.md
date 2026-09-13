# Migration normalization map

Source: migration tip `777bc10c007bb0fa9220ddc6a5fc6230833ba6d5`.

Owning branches: #500 identity/provisioning; #492 peer connection manager; #495 cross-host routing. Existing parent commits were rebased onto current main; these rows account for every subsequent migration commit.

| Source | Change | Owner | Backport | Classification / treatment |
| --- | --- | --- | --- | --- |
| `e8f1a861` | chore: allow staging host2 migration apply | migration branch | `—` | Staging-only / design.  |
| `a0b73ffc` | chore: bootstrap host2 migration CI permissions | migration branch | `—` | Staging-only / design.  |
| `3701c263` | chore: bootstrap CI roles before host2 migration | migration branch | `—` | Staging-only / design.  |
| `3fba0f60` | fix: wrap workload identity issuance config | #500 | `579c47d4` | Durable. Final observed issuance schema retained with regression test. |
| `d03f2cfc` | test: cover workload identity issuance config shape | #500 | `579c47d4` | Durable.  |
| `7e34cb12` | fix: use compute UID attestation resource | #500 | `579c47d4` | Durable.  |
| `6833ad5a` | test: cover compute UID attestation resource | #500 | `579c47d4` | Durable.  |
| `c26e4a72` | fix: align host2 storage precheck with actual layout | #500 | `579c47d4` | Durable. Runtime storage contract retained; does not migrate the serving host. |
| `e54a65ed` | fix: allow legacy proxy hosts before peer admission | #495 | `ee78db2f` | Durable.  |
| `91dcdc46` | test: cover staged peer credential admission | #495 | `ee78db2f` | Durable.  |
| `ebe161c9` | feat: select standby or serving hosts for manual deployments | #500 + #495 | `579c47d4 + ee78db2f` | Durable. Shared selector and VMD integration in #500; proxy integration in #495; no arbitrary labels. |
| `7fe9072b` | fix: reject use4 standby deployment until identity is provisioned | #500 | `579c47d4` | Durable.  |
| `001397ed` | fix: configure the use4 standby identity through deployment variables | #500 + #495 | `579c47d4 + ee78db2f` | Durable. Shared selector in #500, proxy workflow variable wiring in #495. |
| `30a2acf9` | fix: activate standby workload identity and require published credentials | #500 | `579c47d4` | Durable.  |
| `00504acf` | fix: use managed workload principal for CA pool bindings | #500 | `579c47d4` | Durable.  |
| `6c99ed08` | fix: surface captured gcloud errors during peer bootstrap | #500 | `579c47d4` | Durable.  |
| `d3b60b9c` | fix: report capacity stockouts when starting standby hosts | #500 | `579c47d4` | Durable.  |
| `1160deb9` | fix: recreate staging standby with creation-time workload identity | #500 | `579c47d4` | Mixed. Generic creation-time module, attestation flow and bootstrap retained. Staging wiring/provider/attachment ownership retained in 3691e557 because existing state requires the creation-time provider; destructive replacement authorization and applied admission labels excluded. |
| `52fea50b` | Add explicit peer credential providers and CAS staging issuance | #500 + #492 | `579c47d4 + d8eefb32` | Mixed. Provider validation/install retained in #500; plaintext regression in #492 at d8eefb32; staging issuance helper retained only on migration branch. |
| `a2fb2be1` | Manage peer CA custody and issuer permissions with Terraform | #500 | `579c47d4` | Durable.  |
| `5563b203` | fixing | migration branch | `—` | Staging-only / design. Operator-specific IAM default excluded; explicit operator_members remains configurable with empty default. |
| `e769a8db` | fixing | #500 | `579c47d4` | Durable.  |
| `968368c7` | Bootstrap fresh VMD host configuration and require secretsproxy readiness | #500 | `579c47d4` | Durable.  |
| `502157a3` | Require shared cell CA and approved artifacts before host activation | #500 | `579c47d4` | Durable.  |
| `006edb6c` | Wire staging runtime inputs and validate fresh hosts before changes | #500 | `579c47d4` | Durable.  |
| `06319c9e` | Safely retire legacy VMD during fresh host enrollment | #500 | `579c47d4` | Durable.  |
| `e0d0eb90` | Support explicit staging standby collector deployment | #500 | `579c47d4` | Durable.  |
| `387e3f05` | Fix collector script rendering and require persistent activation | #500 | `579c47d4` | Durable.  |
| `09b21b9a` | Discover host interface and private advertisement from default route | #500 | `579c47d4` | Durable.  |
| `08975104` | Provision heartbeat region for named hosts without migrating legacy identity | #500 | `579c47d4` | Durable.  |
| `67b71b83` | Preserve explicit host regions while filling missing enrollment metadata | #500 | `579c47d4` | Durable.  |
| `c94361fe` | Provision explicit schedulable capacity for named hosts | #500 | `579c47d4` | Durable. Host-name capacity defaults replaced by explicit environment/host configuration; no inferred admission limits. |
| `f9a20c76` | Persist template-only data disk mounts during host enrollment | #500 | `579c47d4` | Durable.  |
| `66226c8e` | Allow protected Host 2 admission with label-only plan checks | migration branch | `—` | Staging-only / design. Exact staging replacement/admission guard and plan checker excluded. Generic managed-identity-host retains prevent_destroy and label lifecycle tests. |
| `f584e046` | Verify legacy proxy ingress with fresh control-plane heartbeat | #495 | `ee78db2f` | Durable.  |
| `777bc10c` | Document drain gaps, paused ownership design and staging validation | migration branch | `—` | Staging-only / design. Staging evidence and paused-move design retained on migration branch; drain design informs the separate drain branch. |

Additional normalization regression: #492 `800e24b8` waits for asynchronous stale transport cleanup in the existing regression test.

No staging CI permission bypass, applied admission labels, VM replacement authorization, leaf certificate, host private key, or operator-specific IAM grant is imported. The reusable creation-time module owns the already-created staging Host 2 at the same resource address; prevent_destroy blocks replacement. Other hosts are unchanged.

Validation: Linux deployment tests (91), peer bootstrap/provider (30), template storage (9), identity reconciliation (5), mocked creation-time host (4), mocked CAS custody (4), Terraform formatting. Full Linux Go suite passed. Staging CI subsequently exposed newer-provider state; 3691e557 restores the matching creation-time configuration without applying it.
