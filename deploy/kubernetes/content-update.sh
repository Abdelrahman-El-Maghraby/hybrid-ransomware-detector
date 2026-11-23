#!/usr/bin/env bash
# Install one signed rule pack into a Kubernetes deployment of Aegis Sentinel
# (docs/KUBERNETES.md, "Rule packs"). Operator-run; it changes the cluster:
#
#   deploy/kubernetes/content-update.sh --context CONTEXT --namespace NAMESPACE \
#       --pack aegis-rules-2026.11.02.tar.gz [--yes]
#
# 1. scales the aegis-analysis Deployment to 0 and waits for its Pod to end (the
#    content claim is ReadWriteOncePod: the Job could not mount it otherwise);
# 2. creates the ConfigMap aegis-rulepack-import from the pack and PACK.sig;
# 3. runs the Job in jobs/content-update.yaml with the Deployment's own image and
#    RULEPACK_PUBLIC_KEYS, and prints its log;
# 4. deletes the Job and the ConfigMap it created and scales the Deployment back,
#    whether the install worked or not (a refused pack leaves the old content).
#
# Every kubectl call names --context and --namespace; the current context is
# never read or changed. Scans are refused while the Deployment is at zero.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
ctx="" ns="" pack="" yes=""
while [ $# -gt 0 ]; do
  case "$1" in
    --context) ctx="${2:-}"; shift 2 ;;
    --namespace) ns="${2:-}"; shift 2 ;;
    --pack) pack="${2:-}"; shift 2 ;;
    --yes) yes=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$ctx" ] && [ -n "$ns" ] && [ -n "$pack" ] || { echo "--context, --namespace and --pack are required" >&2; usage; }
[ -f "$pack" ] && [ -f "$pack.sig" ] || { echo "need $pack and $pack.sig" >&2; exit 2; }
size=$(( $(wc -c < "$pack") + $(wc -c < "$pack.sig") ))
if [ "$size" -gt 900000 ]; then
  echo "pack and signature are $size bytes; a ConfigMap holds under 1 MiB." >&2
  echo "See docs/KUBERNETES.md, \"Rule packs\", for larger packs." >&2
  exit 2
fi

k() { kubectl --context "$ctx" --namespace "$ns" "$@"; }
deploy=aegis-analysis job=aegis-content-update cm=aegis-rulepack-import

image="$(k get deployment "$deploy" -o jsonpath='{.spec.template.spec.containers[?(@.name=="analysis")].image}')"
config="$(k get deployment "$deploy" -o jsonpath='{.spec.template.spec.containers[?(@.name=="analysis")].envFrom[0].configMapRef.name}')"
replicas="$(k get deployment "$deploy" -o jsonpath='{.spec.replicas}')"
case "$image" in ''|*[!A-Za-z0-9./:@_-]*) echo "unexpected image reference: '$image'" >&2; exit 1 ;; esac
case "$config" in ''|*[!a-z0-9.-]*) echo "unexpected ConfigMap name: '$config'" >&2; exit 1 ;; esac
if k get job "$job" >/dev/null 2>&1 || k get configmap "$cm" >/dev/null 2>&1; then
  echo "job/$job or configmap/$cm already exists in $ns: remove the leftover first" >&2
  exit 1
fi

echo "context:   $ctx"
echo "namespace: $ns"
echo "pack:      $pack ($size bytes with its signature)"
echo "image:     $image"
echo "scales deployment/$deploy from $replicas to 0 while the pack is installed"
if [ -z "$yes" ]; then
  read -r -p "Proceed? [y/N] " answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "stopped"; exit 1; }
fi

made_cm="" made_job="" scaled=""
cleanup() {
  status=$?
  [ -n "$made_job" ] && k delete job "$job" --wait=true >/dev/null 2>&1 || true
  [ -n "$made_cm" ] && k delete configmap "$cm" >/dev/null 2>&1 || true
  if [ -n "$scaled" ]; then
    k scale deployment "$deploy" --replicas="$replicas" >/dev/null || status=1
    echo "deployment/$deploy scaled back to $replicas"
  fi
  exit "$status"
}
trap cleanup EXIT

k scale deployment "$deploy" --replicas=0 >/dev/null
scaled=1
k wait --for=delete pod -l app.kubernetes.io/name=aegis-sentinel,app.kubernetes.io/component=analysis \
  --timeout=400s >/dev/null 2>&1 || true
if [ -n "$(k get pod -l app.kubernetes.io/component=analysis -o name)" ]; then
  echo "the analysis Pod has not ended; nothing installed" >&2
  exit 1
fi

k create configmap "$cm" --from-file="pack.tar.gz=$pack" --from-file="pack.tar.gz.sig=$pack.sig" >/dev/null
made_cm=1
sed -e "s|AEGIS_IMAGE|$image|" -e "s|AEGIS_CONFIG_MAP|$config|" "$here/jobs/content-update.yaml" \
  | k create -f - >/dev/null
made_job=1

succeeded="" failed=""
for _ in $(seq 1 132); do                      # the Job's own deadline is 600 s
  succeeded="$(k get job "$job" -o jsonpath='{.status.succeeded}')"
  failed="$(k get job "$job" -o jsonpath='{.status.failed}')"
  [ -n "$succeeded" ] || [ -n "$failed" ] && break
  sleep 5
done
echo "== content-update log"
k logs "job/$job" --tail=200 || true
if [ "$succeeded" != "1" ]; then
  echo "== the pack was NOT installed; the previous content stays active" >&2
  exit 1
fi
echo "== pack installed; the analysis Pod reads it when it starts"
