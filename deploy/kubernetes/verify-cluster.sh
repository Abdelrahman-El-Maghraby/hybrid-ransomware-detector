#!/usr/bin/env bash
# Verify a running Kubernetes deployment of Aegis Sentinel on a dedicated test
# cluster (docs/KUBERNETES.md, "Verify"). Operator-run, with the owner's approval
# for that cluster:
#
#   deploy/kubernetes/verify-cluster.sh --context CONTEXT --namespace NAMESPACE \
#       --token-file API_TOKEN_FILE --ca-file CA.pem [--server-name NAME] \
#       [--probe HOST:PORT ...] [--restart-test] [--allow-rwo] [--yes]
#
#   --token-file    the API token the operator created the aegis-api-token Secret from
#   --ca-file       the CA (or self-signed certificate) that signed the TLS certificate
#   --server-name   the name in that certificate (default: localhost); requests go
#                   through `kubectl port-forward` to the Service, with curl --resolve
#   --probe         more destinations the analysis Pod must NOT reach (repeatable),
#                   such as another Service in the cluster or a node address
#   --allow-rwo     the claims are ReadWriteOnce on purpose (docs/KUBERNETES.md)
#   --restart-test  also delete the analysis Pod once (the Deployment replaces it)
#                   and check what survives: persistent state, rule-pack version, a
#                   fresh /tmp, and how long shutdown took
#
# Checks: the deployed objects against check_manifests.py; startup and readiness;
# the isolation gate and container hardening inside the Pod (isolation_gate.py
# verify); the proxy container's hardening; /health, a rejected request without
# and with a wrong token, /ready, and an inert file scanned through TLS.
#
# Every kubectl call names --context and --namespace; the current context is not
# changed. The token is passed to curl in a header file, never on a command line,
# and is never printed. It creates nothing in the cluster; --restart-test deletes
# one Pod and a marker file it wrote. Exit 0 only when every check passed.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
ctx="" ns="" token_file="" ca="" name="localhost" restart="" yes="" rwo="" probes=()
while [ $# -gt 0 ]; do
  case "$1" in
    --context) ctx="${2:-}"; shift 2 ;;
    --namespace) ns="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --ca-file) ca="${2:-}"; shift 2 ;;
    --server-name) name="${2:-}"; shift 2 ;;
    --probe) probes+=("${2:-}"); shift 2 ;;
    --restart-test) restart=1; shift ;;
    --allow-rwo) rwo=--allow-rwo; shift ;;
    --yes) yes=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
if [ -z "$ctx" ] || [ -z "$ns" ] || [ -z "$token_file" ] || [ -z "$ca" ]; then
  echo "--context, --namespace, --token-file and --ca-file are required" >&2
  usage
fi
[ -r "$token_file" ] && [ -r "$ca" ] || { echo "cannot read $token_file or $ca" >&2; exit 2; }
case "$name" in *[!A-Za-z0-9.-]*) echo "bad --server-name" >&2; exit 2 ;; esac

echo "context:   $ctx"
echo "namespace: $ns"
[ -n "$restart" ] && echo "restart test: deletes the analysis Pod once"
if [ -z "$yes" ]; then
  read -r -p "Run the checks against this cluster? [y/N] " answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "stopped"; exit 1; }
fi

k() { kubectl --context "$ctx" --namespace "$ns" "$@"; }
work="$(umask 077 && mktemp -d)"
pf_pid="" marker="aegis-verify-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" fails=0 pod=""
cleanup() {
  [ -n "$pf_pid" ] && kill "$pf_pid" 2>/dev/null
  if [ -n "$pod" ]; then
    k exec "$pod" -c analysis -- python -c "import os,sys; p='/var/lib/aegis/'+sys.argv[1]; os.path.exists(p) and os.remove(p)" "$marker" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then pass "$1 ($3)"; else fail "$1 (got $3, want $2)"; fi; }

# the token, as a curl header file only this user can read
( umask 077; printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' < "$token_file")" > "$work/auth" )
printf 'Authorization: Bearer wrong-token-for-the-verification-run\n' > "$work/wrong"

current_pod() {
  k get pod -l app.kubernetes.io/name=aegis-sentinel,app.kubernetes.io/component=analysis \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}
forward() {
  [ -n "$pf_pid" ] && kill "$pf_pid" 2>/dev/null
  port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
  k port-forward service/aegis-sentinel "$port:8443" >"$work/port-forward.log" 2>&1 &
  pf_pid=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null --connect-timeout 1 --cacert "$ca" --resolve "$name:$port:127.0.0.1" \
      "https://$name:$port/health" && return 0
    sleep 1
  done
  return 1
}
code() {  # code HEADERFILE PATH -> HTTP status
  local hdr=()
  [ -n "$1" ] && hdr=(-H "@$1")
  curl -s -o "$work/body" -w '%{http_code}' --cacert "$ca" --resolve "$name:$port:127.0.0.1" \
    ${hdr[@]+"${hdr[@]}"} "https://$name:$port$2"
}

echo "== deployed objects"
{ k get namespace "$ns" -o yaml; echo "---"
  k get deployment,service,networkpolicy,persistentvolumeclaim,serviceaccount,configmap \
    -l app.kubernetes.io/part-of=aegis-sentinel -o yaml; } > "$work/live.yaml" 2>"$work/get.err" \
  || fail "could not read the deployed objects: $(head -c 300 "$work/get.err")"
if python3 "$here/check_manifests.py" ${rwo:+"$rwo"} "$work/live.yaml"; then pass "deployed objects"; else fail "deployed objects"; fi
extra="$(k get role,rolebinding,horizontalpodautoscaler -o name 2>/dev/null | wc -l | tr -d ' ')"
expect "no Role, RoleBinding or autoscaler in the namespace" 0 "$extra"

echo "== startup and readiness"
if k rollout status deployment/aegis-analysis --timeout=900s >/dev/null; then pass "rollout complete"; else fail "rollout"; fi
pod="$(current_pod)"
[ -n "$pod" ] && pass "analysis Pod $pod running" || fail "no running analysis Pod"
ready="$(k get pod "$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
expect "Pod Ready" True "$ready"

echo "== inside the analysis Pod (isolation_gate.py verify)"
if k exec "$pod" -c analysis -- python /opt/aegis-k8s/isolation_gate.py verify ${probes[@]+"${probes[@]}"}; then
  pass "analysis isolation and hardening"
else
  fail "analysis isolation and hardening (lines above)"
fi
mounted="$(k exec "$pod" -c analysis -- ls /run/secrets/aegis 2>/dev/null | tr '\n' ' ')"
expect "analysis holds only the API token" "api_token " "$mounted"

echo "== inside the proxy container"
status="$(k exec "$pod" -c proxy -- cat /proc/1/status 2>/dev/null)"
expect "proxy CapEff" 0000000000000000 "$(printf '%s\n' "$status" | awk '/^CapEff:/{print $2}')"
expect "proxy NoNewPrivs" 1 "$(printf '%s\n' "$status" | awk '/^NoNewPrivs:/{print $2}')"
expect "proxy Seccomp" 2 "$(printf '%s\n' "$status" | awk '/^Seccomp:/{print $2}')"
expect "proxy uid" 10003 "$(printf '%s\n' "$status" | awk '/^Uid:/{print $2}')"

echo "== through TLS (port-forward to service/aegis-sentinel)"
if ! forward; then
  fail "no TLS answer through the port-forward: $(tail -n 3 "$work/port-forward.log")"
  echo "== $fails check(s) failed"; exit 1
fi
expect "GET /health" 200 "$(code "" /health)"
expect "GET /version without a token" 401 "$(code "" /version)"
expect "GET /version with a wrong token" 401 "$(code "$work/wrong" /version)"
expect "GET /ready with the token" 200 "$(code "$work/auth" /ready)"
printf 'Quarterly figures attached.\n' > "$work/note.txt"
scan="$(curl -s -o "$work/scan.json" -w '%{http_code}' --cacert "$ca" --resolve "$name:$port:127.0.0.1" \
  -H "@$work/auth" -F "file=@$work/note.txt" "https://$name:$port/scan")"
expect "POST /scan of an inert text file" 200 "$scan"
verdict="$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["verdict"], r["scan_status"], r["provenance"]["external_services"])' "$work/scan.json" 2>/dev/null)"
case "$verdict" in "Clean "*) pass "scan result: $verdict" ;; *) fail "scan result: ${verdict:-unreadable}" ;; esac
code "$work/auth" /version >/dev/null
rules_before="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rules"))' "$work/body" 2>/dev/null)"
echo "INFO  intel service: not part of the Kubernetes deployment; external services are off"

if [ -n "$restart" ]; then
  echo "== controlled restart"
  k exec "$pod" -c analysis -- python -c "import sys; [open(d+sys.argv[1],'w').write('x') for d in ('/var/lib/aegis/','/tmp/')]" "$marker" \
    && pass "markers written" || fail "markers written"
  old="$pod" start="$(date +%s)"
  k delete pod "$old" --wait=true --timeout=400s >/dev/null || fail "Pod deletion"
  echo "INFO  shutdown of $old took $(( $(date +%s) - start )) s (grace period 330 s)"
  pod=""
  k rollout status deployment/aegis-analysis --timeout=900s >/dev/null && pass "replacement ready" || fail "replacement ready"
  pod="$(current_pod)"
  [ -n "$pod" ] && [ "$pod" != "$old" ] && pass "new Pod $pod" || fail "no new Pod"
  # shellcheck disable=SC2016
  seen="$(k exec "$pod" -c analysis -- python -c "import os,sys; print(os.path.exists('/var/lib/aegis/'+sys.argv[1]), os.path.exists('/tmp/'+sys.argv[1]))" "$marker")"
  expect "state kept, /tmp fresh" "True False" "$seen"
  forward || fail "TLS after restart"
  code "$work/auth" /version >/dev/null
  rules_after="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rules"))' "$work/body" 2>/dev/null)"
  expect "rule-pack version kept" "$rules_before" "$rules_after"
fi

if [ "$fails" -eq 0 ]; then echo "== every check passed"; else echo "== $fails check(s) failed"; fi
[ "$fails" -eq 0 ]
