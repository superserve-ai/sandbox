# Source before deployment so push runs retain their existing environment.
if [ "${DEPLOY_EVENT:-}" != workflow_dispatch ]; then
  return 0
fi

case "${DEPLOY_TARGET:-standby}" in
  standby|serving) ;;
  *) echo 'Invalid deploy target; expected standby or serving' >&2; exit 1 ;;
esac
case "${DEPLOY_PRODUCTION_CELL:-usw2}" in
  use4|usw2) ;;
  *) echo 'Invalid production cell; expected use4 or usw2' >&2; exit 1 ;;
esac
: "${GCP_REGION:?Refusing an unscoped manual deployment}"

case "$DEPLOY_CELL" in
  staging) standby_host=superserve-vmd-staging-2 ;;
  use4|usw2) ;;
  *) echo 'Invalid deployment cell' >&2; exit 1 ;;
esac
if [ "$DEPLOY_CELL" != staging ] && [ "$DEPLOY_CELL" != "${DEPLOY_PRODUCTION_CELL:-usw2}" ]; then
  echo 'Refusing deployment to an unselected production cell' >&2
  exit 1
fi

if [ "${DEPLOY_TARGET:-standby}" = standby ]; then
  export VMD_LABEL="component=vmd-${DEPLOY_CELL}-standby"
  if [ "$DEPLOY_CELL" != staging ]; then
    : "${GCP_PROJECT:?Refusing a deployment without a project}"
    # Resolve the live role after promotion or rollback, then pin discovery
    # to that instance so a concurrent label swap fails before deployment.
    standby_host=$(set -o pipefail; gcloud compute instances list --project="$GCP_PROJECT" \
      --filter="labels.$VMD_LABEL" --format='csv[no-heading](name,zone)' | \
      python3 -c '
import csv, os, sys
region = os.environ["GCP_REGION"].strip()
rows = [r for r in csv.reader(sys.stdin) if len(r) >= 2 and r[1].split("/")[-1].startswith(region + "-")]
if not region or len(rows) != 1:
    sys.exit("Standby role requires exactly one host in the selected region")
print(rows[0][0])
') || exit 1
  fi
  # Production bootstrap policy belongs to the host, not its serving role.
  if [ "$DEPLOY_CELL" = staging ]; then
    export PEER_IDENTITY_HOSTS="$standby_host"
  fi
  export EXPECTED_STANDBY_HOST="$standby_host"
else
  export VMD_LABEL=component=vmd
fi
