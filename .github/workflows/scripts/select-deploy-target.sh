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
  use4) standby_host=superserve-vmd-use4-2 ;;
  usw2) standby_host=superserve-vmd-usw2-2 ;;
  *) echo 'Invalid deployment cell' >&2; exit 1 ;;
esac
if [ "$DEPLOY_CELL" != staging ] && [ "$DEPLOY_CELL" != "${DEPLOY_PRODUCTION_CELL:-usw2}" ]; then
  echo 'Refusing deployment to an unselected production cell' >&2
  exit 1
fi

if [ "${DEPLOY_TARGET:-standby}" = standby ]; then
  # use4 is reserved: zero matches must fail, never retry the serving label.
  export VMD_LABEL="component=vmd-${DEPLOY_CELL}-standby"
  export PEER_IDENTITY_HOSTS="$standby_host"
  export EXPECTED_STANDBY_HOST="$standby_host"
else
  export VMD_LABEL=component=vmd
fi
