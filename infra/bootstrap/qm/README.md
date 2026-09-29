# Authorized QM bootstrap root

Invoke once per environment with separate administrator-controlled backends.
See the [contract](../../modules/qm/README.md) and [administrator procedure](../../modules/qm/ROLLOUT.md).
This root is absent from automatic deployment workflows.

The reviewed preparation manifest must provide `paired_project_number` for the
selected environment. It is passed as an input rather than discovered through
a live data lookup, so the published contract contains the paired project ID
and number while backend-independent plans remain possible.
