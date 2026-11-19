#!/usr/bin/env bash
# Verify a running Kubernetes deployment of Aegis Sentinel on a dedicated test
# cluster (docs/KUBERNETES.md, "Verify"). Operator-run, with the owner's approval
# for that cluster:
#
#   deploy/kubernetes/verify-cluster.sh --context CONTEXT --namespace NAMESPACE \
#       --token-file API_TOKEN_FILE --ca-file CA.pem --image-digest sha256:HEX \
#       [--proxy-digest sha256:HEX] [--server-name NAME] \
#       [--probe HOST:PORT ...] [--allow-rwo] [--skip-upload-limit]
#       [--control-namespace NAMESPACE] [--drift-test] [--restart-test] [--yes]
#
#   --image-digest  the aegis-sentinel image built from the revision under test:
#                   its registry digest, or for an image loaded into a local
#                   cluster its image ID (docker image inspect -f '{{.Id}}'). Every
#                   analysis and intel container must run it, or the run stops:
#                   the results would describe another build
#   --proxy-digest  the same for aegis-sentinel-proxy (otherwise only printed)
#   --token-file    the API token the operator created the aegis-api-token Secret from
#   --ca-file       the CA (or self-signed certificate) that signed the TLS certificate
#   --server-name   the name in that certificate (default: localhost); requests go
#                   through `kubectl port-forward` to the Service, with curl --resolve
#   --probe         more destinations the analysis Pod must NOT reach (repeatable)
#   --allow-rwo     the claims are ReadWriteOnce on purpose (docs/KUBERNETES.md)
#   --skip-upload-limit  do not send the inert over-limit upload (about 50 MiB)
#   Changes to the cluster (each needs the namespace label below):
#   --control-namespace  a second disposable namespace: a listener and a client
#                   Pod are created there; the client must reach the listener (the
#                   positive control) and the analysis Pod must not (the negative)
#   --drift-test    adds a NetworkPolicy that lets analysis reach DNS, waits for the
#                   readiness probe to take the Pod out of service, removes it, and
#                   waits for the Pod to be ready again
#   --restart-test  deletes the analysis Pod once (the Deployment replaces it) and
#                   checks what survives: state, rule-pack version, a fresh /tmp;
#                   with intel deployed, first deletes the intel Pod once: analysis
#                   must stay Ready and scan while intel is away, and intel's
#                   state claim must survive
#
# The changing options run only in namespaces labelled
# aegis-sentinel.io/verification=disposable by the operator, never in default or
# kube-*. Every kubectl call names --context and a namespace; the current context
# is not read or changed. The token goes to curl in a header file, never on a
# command line, and is never printed. Only objects this run created (named with
# its random marker) are deleted, on exit as well. Exit 0 only when every check
# passed; 1 when one failed; 2 when it refused to start; 3 when none failed but a
# negative check could not be confirmed by its positive control (INCONCLUSIVE).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 2; }
ctx="" ns="" cns="" token_file="" ca="" name="localhost" restart="" drift="" yes="" rwo=""
image_digest="" proxy_digest=""
upload_limit=1 probes=()
while [ $# -gt 0 ]; do
  case "$1" in
    --context) ctx="${2:-}"; shift 2 ;;
    --namespace) ns="${2:-}"; shift 2 ;;
    --control-namespace) cns="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --ca-file) ca="${2:-}"; shift 2 ;;
    --server-name) name="${2:-}"; shift 2 ;;
    --image-digest) image_digest="${2:-}"; shift 2 ;;
    --proxy-digest) proxy_digest="${2:-}"; shift 2 ;;
    --probe) probes+=("${2:-}"); shift 2 ;;
    --restart-test) restart=1; shift ;;
    --drift-test) drift=1; shift ;;
    --skip-upload-limit) upload_limit=""; shift ;;
    --allow-rwo) rwo=--allow-rwo; shift ;;
    --yes) yes=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
if [ -z "$ctx" ] || [ -z "$ns" ] || [ -z "$token_file" ] || [ -z "$ca" ] || [ -z "$image_digest" ]; then
  echo "--context, --namespace, --token-file, --ca-file and --image-digest are required" >&2
  usage
fi
for d in "$image_digest" "$proxy_digest"; do
  case "$d" in
    ""|sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "refused: a digest is sha256: and 64 hex digits, not $d" >&2; exit 2 ;;
  esac
  case "${d#sha256:}" in *[!0123456789abcdef]*) echo "refused: bad digest $d" >&2; exit 2 ;; esac
done
for n in "$ns" "$cns"; do
  case "$n" in
    default|kube-system|kube-public|kube-node-lease)
      echo "refused: namespace $n is shared; use a dedicated test namespace" >&2; exit 2 ;;
    *[!abcdefghijklmnopqrstuvwxyz0123456789-]*) echo "refused: bad namespace name $n" >&2; exit 2 ;;
  esac
done
if [ -n "$cns" ] && [ "$cns" = "$ns" ]; then
  echo "refused: --control-namespace must differ from --namespace" >&2; exit 2
fi
[ -r "$token_file" ] && [ -r "$ca" ] || { echo "cannot read $token_file or $ca" >&2; exit 2; }
case "$name" in *[!A-Za-z0-9.-]*) echo "bad --server-name" >&2; exit 2 ;; esac
changes="${restart:+ restart-test}${drift:+ drift-test}${cns:+ control-namespace}"

echo "context:   $ctx"
echo "namespace: $ns${cns:+ (control: $cns)}"
[ -n "$changes" ] && echo "changes to the cluster:$changes"
if [ -z "$yes" ]; then
  read -r -p "Run the checks against this cluster? [y/N] " answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "stopped"; exit 1; }
fi

k() { kubectl --context "$ctx" --namespace "$ns" "$@"; }
kc() { kubectl --context "$ctx" --namespace "$cns" "$@"; }
work="$(umask 077 && mktemp -d)"
marker="aegis-verify-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
pf_pid="" fails=0 unsure=0 pod="" ipod="" intel_marker="" created=()  # created: "namespace kind/name"
cleanup() {
  [ -n "$pf_pid" ] && kill "$pf_pid" 2>/dev/null
  local item
  for item in ${created[@]+"${created[@]}"}; do
    if [ "${item%% *}" = "$ns" ]; then
      k delete "${item#* }" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    else
      kc delete "${item#* }" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    fi
  done
  if [ -n "$pod" ]; then
    k exec "$pod" -c analysis -- python -c "import os,sys; p='/var/lib/aegis/'+sys.argv[1]; os.path.exists(p) and os.remove(p)" "$marker" >/dev/null 2>&1 || true
  fi
  if [ -n "$intel_marker" ]; then
    ipod="$(current_intel_pod)"
    [ -n "$ipod" ] && k exec "$ipod" -c intel -- python -c "import os,sys; p='/var/lib/aegis-intel/'+sys.argv[1]; os.path.exists(p) and os.remove(p)" "$marker" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
inconclusive() { echo "INCONCLUSIVE  $*"; unsure=$((unsure + 1)); }
expect() { if [ "$2" = "$3" ]; then pass "$1 ($3)"; else fail "$1 (got $3, want $2)"; fi; }
refuse() { echo "REFUSED  $*" >&2; exit 2; }

echo "== preflight (read-only)"
minor="$(k version -o json 2>/dev/null | python3 -c 'import json,sys; v=json.load(sys.stdin)["serverVersion"]; print(int("".join(c for c in v["minor"] if c.isdigit())))' 2>/dev/null)"
[ -n "$minor" ] || refuse "cannot reach the API server with context $ctx"
[ "$minor" -ge 29 ] || refuse "Kubernetes 1.$minor; 1.29 or later is required (ReadWriteOncePod)"
pass "API server 1.$minor"
label='{.metadata.labels.aegis-sentinel\.io/verification}'
k get namespace "$ns" >/dev/null 2>&1 || refuse "namespace $ns does not exist"
if [ -n "$changes" ]; then
  [ "$(k get namespace "$ns" -o jsonpath="$label" 2>/dev/null)" = "disposable" ] \
    || refuse "$ns lacks the label aegis-sentinel.io/verification=disposable needed for:$changes"
fi
if [ -n "$cns" ]; then
  kc get namespace "$cns" >/dev/null 2>&1 || refuse "namespace $cns does not exist"
  [ "$(kc get namespace "$cns" -o jsonpath="$label" 2>/dev/null)" = "disposable" ] \
    || refuse "$cns lacks the label aegis-sentinel.io/verification=disposable"
fi
can() { [ "$(k auth can-i "$@" 2>/dev/null)" = "yes" ] || refuse "not allowed: $* in $ns"; }
canc() { [ "$(kc auth can-i "$@" 2>/dev/null)" = "yes" ] || refuse "not allowed: $* in $cns"; }
can get pods; can create pods/exec; can create pods/portforward; can get deployments
[ -n "$restart" ] && can delete pods
[ -n "$drift" ] && { can create networkpolicies; can delete networkpolicies; }
[ -n "$cns" ] && { canc create pods; canc create services; canc delete pods; canc delete services
                   canc create pods/exec; canc get pods; }
pass "permissions for the selected checks"

# the token, as a curl header file only this user can read
( umask 077; printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' < "$token_file")" > "$work/auth" )
printf 'Authorization: Bearer wrong-token-for-the-verification-run\n' > "$work/wrong"

current_pod() {
  k get pod -l app.kubernetes.io/name=aegis-sentinel,app.kubernetes.io/component=analysis \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}
current_intel_pod() {
  k get pod -l app.kubernetes.io/name=aegis-sentinel,app.kubernetes.io/component=intel \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}
# The images the Pod's containers really run (init containers too), against the
# digests of the build under test: an older image must not pass as this revision.
check_images() {  # check_images POD
  local cname id want bad=0
  while read -r cname id; do
    [ -n "$cname" ] || continue
    case "$cname" in proxy|intel-proxy) want="$proxy_digest" ;; *) want="$image_digest" ;; esac
    if [ -z "$want" ]; then echo "INFO  $1/$cname runs ${id:-an unknown image}"; continue; fi
    case "$id" in
      *"$want") pass "$1/$cname runs the image under test" ;;
      *) fail "$1/$cname runs ${id:-an unknown image}, not $want"; bad=1 ;;
    esac
  done <<EOF_IMAGES
$(k get pod "$1" -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{" "}{.imageID}{"\n"}{end}{range .status.containerStatuses[*]}{.name}{" "}{.imageID}{"\n"}{end}' 2>/dev/null)
EOF_IMAGES
  if [ "$bad" -ne 0 ]; then
    echo "== stopped: $1 does not run the build under test, so no result would describe it"
    exit 1
  fi
}
ready_state() { k get pod "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null; }
wait_ready() {  # wait_ready POD True|False SECONDS -> seconds taken, or empty
  local start; start="$(date +%s)"
  while [ $(( $(date +%s) - start )) -lt "$3" ]; do
    [ "$(ready_state "$1")" = "$2" ] && { echo $(( $(date +%s) - start )); return 0; }
    sleep 5
  done
  return 1
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
in_analysis() { k exec "$pod" -c analysis -- python -c "$@"; }

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
expect "Pod Ready" True "$(ready_state "$pod")"
k logs "$pod" -c prepare-state >/dev/null 2>&1 && pass "prepare-state finished" || fail "prepare-state log"
[ -n "$pod" ] && check_images "$pod"
intel_ip="$(k get service aegis-intel -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
if [ -n "$intel_ip" ]; then
  k rollout status deployment/aegis-intel --timeout=600s >/dev/null && pass "intel rollout complete" || fail "intel rollout"
  ipod="$(current_intel_pod)"
  [ -n "$ipod" ] && pass "intel Pod $ipod running" || fail "no running intel Pod"
  [ -n "$ipod" ] && check_images "$ipod"
fi

echo "== inside the analysis Pod (isolation_gate.py verify)"
if k exec "$pod" -c analysis -- python /opt/aegis-k8s/isolation_gate.py verify ${probes[@]+"${probes[@]}"}; then
  pass "analysis isolation and hardening"
else
  fail "analysis isolation and hardening (lines above)"
fi

echo "== secrets, socket and volumes"
# positive control first: each probe must see its own container's secret
expect "analysis sees its API token, not the TLS key" "True False" \
  "$(in_analysis "import os; print(os.path.isfile('/run/secrets/aegis/api_token'), os.path.exists('/etc/caddy/tls'))" 2>/dev/null)"
expect "analysis holds only the API token" "api_token" \
  "$(in_analysis "import os; print(' '.join(sorted(n for n in os.listdir('/run/secrets/aegis') if not n.startswith('.'))))" 2>/dev/null)"
if k exec "$pod" -c proxy -- test -f /etc/caddy/tls/cert.pem >/dev/null 2>&1; then
  if k exec "$pod" -c proxy -- test -e /run/secrets/aegis/api_token >/dev/null 2>&1; then
    fail "the proxy can see the API token"
  else
    pass "proxy sees its certificate, not the API token"
  fi
else
  fail "proxy secret check inconclusive: the positive control (its own certificate) failed"
fi
owner="$(in_analysis "import os; s=os.stat('/var/lib/aegis/RansomwareScanner'); print(s.st_uid)" 2>/dev/null)"
expect "state folder owned by the service user" 10001 "$owner"
echo "INFO  $(in_analysis "import os,stat; s=os.stat('/run/aegis/api/api.sock'); print('api.sock mode', oct(stat.S_IMODE(s.st_mode)), 'uid', s.st_uid, 'gid', s.st_gid)" 2>/dev/null)"

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
if [ -n "$upload_limit" ]; then
  # an inert file of zeros one byte over the limit: the API itself must refuse it
  # (JSON 413), which also shows the proxy's cap is above the API's
  mb="$(in_analysis "import os; print(os.environ.get('AEGIS_API_MAX_UPLOAD_MB') or 50)" 2>/dev/null)"
  python3 -c 'import sys; open(sys.argv[1], "wb").truncate(int(float(sys.argv[2]) * 1048576) + 1)' \
    "$work/over.bin" "${mb:-50}"
  over="$(curl -s -o "$work/over.json" -w '%{http_code}' --cacert "$ca" --resolve "$name:$port:127.0.0.1" \
    -H "@$work/auth" -F "file=@$work/over.bin" "https://$name:$port/scan")"
  rm -f "$work/over.bin"
  expect "POST /scan one byte over ${mb:-50} MiB" 413 "$over"
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))["detail"]' "$work/over.json" 2>/dev/null \
    && pass "the 413 came from the API (JSON)" || fail "the 413 did not come from the API (the proxy's cap?)"
fi
code "$work/auth" /version >/dev/null
rules_before="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rules"))' "$work/body" 2>/dev/null)"
intel_ok="" intel_to_analysis=""
if [ -z "$intel_ip" ]; then
  echo "INFO  intel service: not deployed (components/intel); external services are off"
else
  echo "== intel over TLS (option E, Service $intel_ip:9443)"
  # the real client, its token, the private CA and the certificate's name; "wrong"
  # swaps the token, "wrongname" the name the certificate must carry
  call='import dataclasses, sys
from engine.config import CONFIG
from core.intel_client import IntelClient, IntelError, client_from_config
c = client_from_config(CONFIG)
if sys.argv[1] == "wrong":
    c = IntelClient("", "x" * 40, tls=c.tls)
elif sys.argv[1] == "wrongname":
    c = IntelClient("", c.token, tls=dataclasses.replace(c.tls, server_name="wrong-name.invalid"))
try:
    c.call("GET", "/v1/capabilities", timeout=15); print("200")
except IntelError as e:
    print(e.status or "unreachable")'
  first="$(in_analysis "$call" ok 2>/dev/null)"
  expect "analysis to intel with its token (TLS verified)" 200 "$first"
  [ "$first" = 200 ] && intel_ok=1
  if [ -n "$intel_ok" ]; then         # negatives count only once intel is shown to answer
    expect "analysis to intel with a wrong token" 401 "$(in_analysis "$call" wrong 2>/dev/null)"
    expect "analysis to intel expecting another certificate name (nothing sent)" unreachable \
      "$(in_analysis "$call" wrongname 2>/dev/null)"
  else
    inconclusive "intel did not answer analysis, so the token and name checks prove nothing"
  fi
  # secrets per container; each line starts with that container's own secret
  expect "analysis holds the intel token and CA, not intel's credentials" "True True False" \
    "$(in_analysis "import os; print(os.path.isfile('/run/secrets/aegis-intel/intel_token'), os.path.isfile('/etc/aegis-intel-ca/ca.crt'), os.path.exists('/run/secrets/aegis-intel-credentials'))" 2>/dev/null)"
  expect "intel holds its credentials and token, not the TLS key" "True True False" \
    "$(k exec "$ipod" -c intel -- python -c "import os; print(os.path.isdir('/run/secrets/aegis-intel-credentials'), os.path.isfile('/run/secrets/aegis-intel/intel_token'), os.path.exists('/etc/caddy/tls'))" 2>/dev/null)"
  if k exec "$ipod" -c intel-proxy -- test -f /etc/caddy/tls/cert.pem >/dev/null 2>&1; then
    if k exec "$ipod" -c intel-proxy -- test -e /run/secrets/aegis-intel >/dev/null 2>&1 \
       || k exec "$ipod" -c intel-proxy -- test -e /run/secrets/aegis-intel-credentials >/dev/null 2>&1; then
      fail "the intel proxy can see the intel token or credentials"
    else
      pass "intel proxy sees its certificate, not the token or credentials"
    fi
  else
    fail "intel proxy secret check inconclusive: the positive control (its own certificate) failed"
  fi
  echo "INFO  $(k exec "$ipod" -c intel -- python -c "import os,stat; s=os.stat('/var/lib/aegis-intel'); print('intel state mode', oct(stat.S_IMODE(s.st_mode)), 'uid', s.st_uid, 'gid', s.st_gid)" 2>/dev/null)"
  analysis_ip="$(k get pod "$pod" -o jsonpath='{.status.podIP}')"
  reach_from_intel="import socket,sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5).close(); print('connected')
except OSError as e:
    print('blocked')"
  intel_to_analysis="$(k exec "$ipod" -c intel -- python -c "$reach_from_intel" "$analysis_ip" 8443 2>/dev/null)"
  [ -n "$cns" ] || inconclusive "intel to analysis $analysis_ip:8443: ${intel_to_analysis:-no answer}; the positive control needs --control-namespace"
  echo "INFO  the analysis Pod's TLS proxy shares analysis's network and can open 9443; it holds no intel token (401)"
fi

if [ -n "$cns" ]; then
  echo "== controlled network check (control namespace $cns)"
  image="$(k get deployment aegis-analysis -o jsonpath='{.spec.template.spec.containers[?(@.name=="analysis")].image}')"
  listener="import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', 8080)); s.listen(8)
while True:
    c, _ = s.accept(); c.sendall(b'aegis-verify\n'); c.close()"
  for role in echo client; do
    cmd="$listener"; [ "$role" = client ] && cmd="import time; time.sleep(900)"
    python3 - "$marker" "$role" "$image" "$cmd" > "$work/$role.json" <<'EOF'
import json, sys
marker, role, image, cmd = sys.argv[1:]
print(json.dumps({"apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": f"{marker}-{role}", "labels": {"aegis-verify": marker, "role": role}},
    "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
             "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                 "seccompProfile": {"type": "RuntimeDefault"}},
             "containers": [{"name": role, "image": image, "command": ["python", "-c", cmd],
                             "securityContext": {"allowPrivilegeEscalation": False,
                                                 "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}},
                             "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}}}]}}))
EOF
    created+=("$cns pod/$marker-$role")
    kc create -f "$work/$role.json" >/dev/null || fail "create $role Pod"
  done
  created+=("$cns service/$marker")
  printf '{"apiVersion":"v1","kind":"Service","metadata":{"name":"%s"},"spec":{"selector":{"aegis-verify":"%s","role":"echo"},"ports":[{"protocol":"TCP","port":8080,"targetPort":8080}]}}\n' \
    "$marker" "$marker" > "$work/service.json"
  kc create -f "$work/service.json" >/dev/null || fail "create Service"
  kc wait --for=condition=Ready "pod/$marker-echo" "pod/$marker-client" --timeout=300s >/dev/null \
    || fail "control Pods not ready"
  svc_ip="$(kc get service "$marker" -o jsonpath='{.spec.clusterIP}')"
  pod_ip="$(kc get pod "$marker-echo" -o jsonpath='{.status.podIP}')"
  reach="import socket,sys; s=socket.create_connection((sys.argv[1], 8080), timeout=5); print(s.recv(32).decode().strip())"
  positive="$(kc exec "$marker-client" -- python -c "$reach" "$svc_ip" 2>/dev/null)"
  if [ "$positive" = "aegis-verify" ]; then
    pass "positive control: an unrestricted Pod reaches $svc_ip:8080 and $(kc exec "$marker-client" -- python -c "$reach" "$pod_ip" 2>/dev/null | sed "s/aegis-verify/$pod_ip:8080/")"
    if k exec "$pod" -c analysis -- python /opt/aegis-k8s/isolation_gate.py verify "$svc_ip:8080" "$pod_ip:8080" >"$work/negative.log" 2>&1; then
      pass "negative: the analysis Pod does not reach the same listener"
    else
      fail "negative: the analysis Pod reached the listener or a check failed: $(grep FAIL "$work/negative.log" | head -3)"
    fi
  else
    fail "inconclusive: the positive control could not reach the listener, so a blocked result from analysis would prove nothing"
  fi
  if [ -n "$intel_ip" ]; then
    try_reach="import socket,sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5).close(); print('connected')
except OSError:
    print('blocked')"
    # intel answers on 9443 (analysis reached it above): only then is "blocked" from
    # another namespace a result
    if [ -n "$intel_ok" ]; then
      expect "a Pod outside analysis cannot reach intel $intel_ip:9443" blocked \
        "$(kc exec "$marker-client" -- python -c "$try_reach" "$intel_ip" 9443 2>/dev/null)"
    else
      inconclusive "intel did not answer analysis, so a blocked control Pod proves nothing"
    fi
    # analysis's 8443 admits any source in the base: the control Pod must connect
    # (positive), and only then does intel's blocked attempt count
    if [ "$(kc exec "$marker-client" -- python -c "$try_reach" "$analysis_ip" 8443 2>/dev/null)" = connected ]; then
      pass "positive control: a Pod in $cns reaches analysis $analysis_ip:8443"
      expect "intel cannot reach analysis ($analysis_ip:8443)" blocked "$intel_to_analysis"
    else
      inconclusive "the control Pod cannot reach analysis $analysis_ip:8443 (ingress narrowed in the overlay?), so intel's blocked attempt ($intel_to_analysis) proves nothing"
    fi
  fi
  dns="$(kc exec "$marker-client" -- python -c "import socket; socket.getaddrinfo('kubernetes.default.svc', 443); print('resolved')" 2>/dev/null)"
  expect "positive control: cluster DNS answers an unrestricted Pod (so the gate's DNS probe is meaningful)" resolved "$dns"
fi

if [ -n "$drift" ]; then
  echo "== isolation drift after startup (readiness)"
  created+=("$ns networkpolicy/$marker-drift")
  k apply -f - >/dev/null <<EOF || fail "drift policy applied"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: $marker-drift}
spec:
  podSelector:
    matchLabels: {app.kubernetes.io/name: aegis-sentinel, app.kubernetes.io/component: analysis}
  policyTypes: [Egress]
  egress:
    - ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
EOF
  if took="$(wait_ready "$pod" False 180)"; then
    pass "readiness took the Pod out of service ${took} s after DNS egress was allowed"
  else
    fail "the Pod stayed Ready for 180 s with DNS egress allowed"
  fi
  k delete networkpolicy "$marker-drift" --wait=true >/dev/null 2>&1 || fail "drift policy removed"
  if took="$(wait_ready "$pod" True 300)"; then
    pass "Ready again ${took} s after the drift policy was removed"
  else
    fail "the Pod did not become Ready again within 300 s"
  fi
fi

if [ -n "$restart" ] && [ -n "$intel_ip" ] && [ -n "$ipod" ]; then
  echo "== intel restart: temporary unavailability, state, shutdown"
  intel_marker=1
  k exec "$ipod" -c intel -- python -c "import sys; open('/var/lib/aegis-intel/'+sys.argv[1],'w').write('x')" "$marker" \
    && pass "marker written to intel's state claim (writable by uid 10002)" || fail "intel state claim not writable"
  old_ipod="$ipod" start="$(date +%s)"
  k delete pod "$old_ipod" --wait=false >/dev/null || fail "intel Pod deletion"
  away=""
  for _ in $(seq 1 30); do                   # Recreate: no intel Pod for a while
    away="$(in_analysis "$call" ok 2>/dev/null)"
    [ "$away" != 200 ] && break
    sleep 2
  done
  if [ "$away" != 200 ]; then
    pass "while intel is away, analysis's call fails instead of hanging (${away:-no output})"
    expect "analysis stays Ready while intel is away" True "$(ready_state "$pod")"
    scan="$(curl -s -o "$work/scan-away.json" -w '%{http_code}' --cacert "$ca" --resolve "$name:$port:127.0.0.1" \
      -H "@$work/auth" -F "file=@$work/note.txt" "https://$name:$port/scan")"
    expect "POST /scan of an inert file while intel is away" 200 "$scan"
    echo "INFO  scan while intel is away: $(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["verdict"], r["scan_status"], r["provenance"]["external_services"])' "$work/scan-away.json" 2>/dev/null)"
  else
    inconclusive "intel answered throughout its restart; the unavailable state was not observed"
  fi
  k wait --for=delete "pod/$old_ipod" --timeout=700s >/dev/null 2>&1 || fail "old intel Pod still there after 700 s"
  echo "INFO  shutdown of $old_ipod took $(( $(date +%s) - start )) s (grace period 630 s)"
  k rollout status deployment/aegis-intel --timeout=600s >/dev/null && pass "intel replacement ready" || fail "intel replacement ready"
  ipod="$(current_intel_pod)"
  [ -n "$ipod" ] && [ "$ipod" != "$old_ipod" ] && pass "new intel Pod $ipod" || fail "no new intel Pod"
  [ -n "$ipod" ] && check_images "$ipod"
  expect "intel state kept across the Pod replacement" True \
    "$(k exec "$ipod" -c intel -- python -c "import os,sys; print(os.path.exists('/var/lib/aegis-intel/'+sys.argv[1]))" "$marker" 2>/dev/null)"
  back=""
  for _ in $(seq 1 30); do                   # the same ClusterIP, a new Pod behind it
    back="$(in_analysis "$call" ok 2>/dev/null)"
    [ "$back" = 200 ] && break
    sleep 3
  done
  expect "analysis reaches the new intel Pod through the same address" 200 "$back"
fi

if [ -n "$restart" ]; then
  echo "== controlled restart"
  in_analysis "import sys; [open(d+sys.argv[1],'w').write('x') for d in ('/var/lib/aegis/','/tmp/')]" "$marker" \
    && pass "markers written" || fail "markers written"
  old="$pod" start="$(date +%s)"
  k delete pod "$old" --wait=true --timeout=400s >/dev/null || fail "Pod deletion"
  echo "INFO  shutdown of $old took $(( $(date +%s) - start )) s (grace period 330 s)"
  pod=""
  k rollout status deployment/aegis-analysis --timeout=900s >/dev/null && pass "replacement ready" || fail "replacement ready"
  pod="$(current_pod)"
  [ -n "$pod" ] && [ "$pod" != "$old" ] && pass "new Pod $pod" || fail "no new Pod"
  [ -n "$pod" ] && check_images "$pod"
  seen="$(in_analysis "import os,sys; print(os.path.exists('/var/lib/aegis/'+sys.argv[1]), os.path.exists('/tmp/'+sys.argv[1]))" "$marker")"
  expect "state kept, /tmp fresh" "True False" "$seen"
  forward || fail "TLS after restart"
  code "$work/auth" /version >/dev/null
  rules_after="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rules"))' "$work/body" 2>/dev/null)"
  expect "rule-pack version kept" "$rules_before" "$rules_after"
fi

if [ "$fails" -ne 0 ]; then
  echo "== $fails check(s) failed, $unsure inconclusive"; exit 1
elif [ "$unsure" -ne 0 ]; then
  echo "== no check failed, but $unsure could not be confirmed (INCONCLUSIVE above)"; exit 3
fi
echo "== every check passed"
