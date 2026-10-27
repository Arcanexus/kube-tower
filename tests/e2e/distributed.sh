#!/usr/bin/env bash
# End-to-end test of the chart's distributed mode on a kind cluster, with the kube-tower:e2e image
# loaded in it: every pod starts, a scan goes through the worker and trivy pods (tasks and results in
# Valkey), the UI pods show the state the controller publishes in Valkey, and a standby controller takes
# over (with the inventory kept in Valkey) when the active one stops.
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
            "$@" || true
            return 1
        fi
        sleep 5
    done
    log "$what"
}

# GET <url> from a pod (target: pod/<name> or deploy/<name>), with the Python of the image
fetch() {
    kubectl -n "$NS" exec "$1" -- python -c \
        'import sys, urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=20).read().decode())' "$2"
}
snapshot() { fetch deploy/"$RELEASE"-ui http://127.0.0.1:8080/api/snapshot; }
scanned() { snapshot | jq -e '.finished_at != null and (.images | length) > 0'; }
vulnerabilities_scanned() { snapshot | jq -e '.vulnerabilities_finished_at != null'; }
holder() { kubectl -n "$NS" get lease "$RELEASE"-controller -o jsonpath='{.spec.holderIdentity}'; }
# The controller Service (its /metrics) reaches the pod of the active controller only (labelled by it)
active_endpoint() {
    [ "$(kubectl -n "$NS" get pods -l kube-tower.arcanexus.com/active-controller=true -o name)" = "pod/$(holder)" ] &&
        [ "$(kubectl -n "$NS" get endpoints "$RELEASE"-controller -o json | jq '[.subsets[]?.addresses[]?] | length')" = "1" ]
}

log "install"
kubectl create namespace "$NS"
helm install "$RELEASE" charts/kube-tower -n "$NS" -f tests/e2e/distributed-values.yaml --wait --timeout 10m
kubectl -n "$NS" get pods -o wide

log "one active controller"
wait_for 120 "the controller Service reaches the active controller" active_endpoint
first=$(holder)
[ -n "$first" ]
echo "active controller: $first"

wait_for 600 "a scan went through the worker pods" scanned
snapshot | jq '{finished_at, images: (.images | length), charts: (.charts | length), errors: (.errors | length)}'
wait_for 900 "the trivy pod scanned the vulnerabilities" vulnerabilities_scanned
snapshot | jq '[.images[] | select(.vulnerabilities != null and .vulnerabilities.message == null)] | length'

# Every ui pod shows the same inventory, published by the controller in Valkey
for pod in $(kubectl -n "$NS" get pods -l app.kubernetes.io/component=ui -o name); do
    count=$(fetch "$pod" http://127.0.0.1:8080/api/snapshot | jq '.images | length')
    echo "$pod: $count images"
    [ "$count" -gt 0 ]
done
# The pages answer, and the metrics come from the controller
# grep reads all of a page (no -q): with pipefail, a fetch cut short by `grep -q` fails with SIGPIPE (141)
fetch deploy/"$RELEASE"-ui http://127.0.0.1:8080/ | grep kube-tower >/dev/null
fetch deploy/"$RELEASE"-ui http://"$RELEASE"-controller:8080/metrics | grep kube_tower_image_outdated >/dev/null

log "every pod tells it is there and ships its log lines"
pods() { kubectl -n "$NS" get pods -l 'app.kubernetes.io/component in (controller,ui,worker,trivy)' -o jsonpath='{.items[*].metadata.name}'; }
all_reported() {
    page=$(fetch deploy/"$RELEASE"-ui http://127.0.0.1:8080/administration/processes) || return 1
    for pod in $(pods); do grep -q "<code>$pod</code>" <<<"$page" || return 1; done
    ! grep -q 'process-lost' <<<"$page"
}
wait_for 60 "the Administration page lists every pod, none lost" all_reported
worker_logs() { fetch deploy/"$RELEASE"-ui "http://127.0.0.1:8080/logs?role=worker" | grep "class=\"log-source\" title=\"Roles: worker\">$RELEASE-worker-" >/dev/null; }
wait_for 60 "the Logs page shows the lines of the worker pods" worker_logs

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
