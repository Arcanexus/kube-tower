#!/usr/bin/env bash
# End-to-end test of the chart's distributed mode on a kind cluster, with the kube-tower:e2e image
# loaded in it: every pod starts, a scan goes through the worker and trivy pods, the UI pods show it,
# and a standby controller takes over (with the inventory kept in Valkey) when the active one stops.
set -euo pipefail

NS=kube-tower
RELEASE=kube-tower
cd "$(dirname "$0")/../.."

log() { echo "--- $*"; }

diagnose() {
    log "diagnostics"
    kubectl -n "$NS" get pods,svc,lease -o wide || true
    for pod in $(kubectl -n "$NS" get pods -o name); do
        echo "=== $pod"
        kubectl -n "$NS" logs "$pod" --all-containers --tail=60 || true
    done
}
trap 'diagnose' ERR

# Waits until the command succeeds: wait_for <seconds> <description> <command...>
wait_for() {
    local timeout=$1 what=$2
    shift 2
    local end=$((SECONDS + timeout))
    until "$@" >/dev/null 2>&1; do
        if ((SECONDS > end)); then
            echo "timeout after ${timeout}s: $what" >&2
            return 1
        fi
        sleep 5
    done
    log "$what"
}

snapshot() { kubectl -n "$NS" exec deploy/"$RELEASE"-ui -- wget -qO- http://localhost:8080/api/snapshot; }
scanned() { snapshot | jq -e '.finished_at != null and (.images | length) > 0'; }
vulnerabilities_scanned() { snapshot | jq -e '.vulnerabilities_finished_at != null'; }
holder() { kubectl -n "$NS" get lease "$RELEASE"-controller -o jsonpath='{.spec.holderIdentity}'; }
# The internal Service reaches the pod of the active controller only (labelled by it)
active_endpoint() {
    [ "$(kubectl -n "$NS" get pods -l kube-tower.arcanexus.com/active-controller=true -o name)" = "pod/$(holder)" ] &&
        [ "$(kubectl -n "$NS" get endpoints "$RELEASE"-internal -o json | jq '[.subsets[]?.addresses[]?] | length')" = "1" ]
}

log "install"
kubectl create namespace "$NS"
kubectl -n "$NS" create secret generic kube-tower-internal --from-literal=token="$(openssl rand -hex 32)"
helm install "$RELEASE" charts/kube-tower -n "$NS" -f tests/e2e/distributed-values.yaml --wait --timeout 10m
kubectl -n "$NS" get pods -o wide

log "one active controller"
wait_for 120 "the internal Service reaches the active controller" active_endpoint
first=$(holder)
[ -n "$first" ]
echo "active controller: $first"

wait_for 600 "a scan went through the worker pods" scanned
snapshot | jq '{finished_at, images: (.images | length), charts: (.charts | length), errors: (.errors | length)}'
wait_for 900 "the trivy pod scanned the vulnerabilities" vulnerabilities_scanned
snapshot | jq '[.images[] | select(.vulnerabilities != null and .vulnerabilities.message == null)] | length'

# Every ui pod shows the same inventory, read from the controller
for pod in $(kubectl -n "$NS" get pods -l app.kubernetes.io/component=ui -o name); do
    count=$(kubectl -n "$NS" exec "$pod" -- wget -qO- http://localhost:8080/api/snapshot | jq '.images | length')
    echo "$pod: $count images"
    [ "$count" -gt 0 ]
done
# The pages answer, and the metrics come from the controller
kubectl -n "$NS" exec deploy/"$RELEASE"-ui -- wget -qO- http://localhost:8080/ | grep -q kube-tower
kubectl -n "$NS" exec deploy/"$RELEASE"-ui -- wget -qO- http://"$RELEASE"-internal:8080/metrics | grep -q kube_tower_images

log "failover"
images=$(snapshot | jq '.images | length')
kubectl -n "$NS" delete pod "$first" --wait=false
standby_took_over() { h=$(holder) && [ -n "$h" ] && [ "$h" != "$first" ] && active_endpoint; }
wait_for 120 "the standby controller took over" standby_took_over
echo "active controller: $(holder)"
# The new controller read the inventory from Valkey: no new scan needed to show it
same_inventory() { [ "$(snapshot | jq '.images | length')" = "$images" ]; }
wait_for 60 "the UI shows the inventory kept in Valkey" same_inventory
kubectl -n "$NS" logs "$(holder)" | grep -E "snapshot read from Redis: [1-9]"

log "rollout of the controller"
kubectl -n "$NS" rollout restart deploy/"$RELEASE"-controller
kubectl -n "$NS" rollout status deploy/"$RELEASE"-controller --timeout=180s
wait_for 120 "an active controller after the rollout" active_endpoint

log "ok"
