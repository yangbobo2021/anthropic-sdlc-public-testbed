#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 boob.yang
set -euo pipefail
umask 077

mkdir -p evidence
scratch=$(mktemp -d)
bao_pid=''
production_pid=''
cleanup() {
  for pid in "$production_pid" "$bao_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  rm -rf -- "$scratch"
}
trap cleanup EXIT
artifact=package/service.tar
printf '%s  %s\n' "${EXPECTED_DIGEST:?}" "$artifact" | sha256sum -c
signer="$GITHUB_REPOSITORY/.github/workflows/promotion-sandbox.yml"
verify() {
  local path="$1" source="$2" workflow="$3"
  gh attestation verify "$path" -R "$GITHUB_REPOSITORY" \
    --source-ref refs/heads/main --source-digest "$source" \
    --signer-workflow "$workflow" --signer-digest "$GITHUB_SHA"
}
must_fail() {
  local name="$1"
  shift
  if "$@" > "evidence/$name.txt" 2>&1; then
    printf 'Unexpected success for %s\n' "$name" >&2
    return 1
  fi
}
verify "$artifact" "$GITHUB_SHA" "$signer" > evidence/attestation.txt
must_fail wrong-source verify "$artifact" "$(printf '%040d' 0)" "$signer"
must_fail wrong-signer verify "$artifact" "$GITHUB_SHA" "$GITHUB_REPOSITORY/.github/workflows/pr-checks.yml"
mkdir "$scratch/tampered"
cp "$artifact" "$scratch/tampered/service.tar"
printf 'different content\n' >> "$scratch/tampered/service.tar"
must_fail altered-artifact verify "$scratch/tampered/service.tar" "$GITHUB_SHA" "$signer"

jq -e --arg commit "$GITHUB_SHA" --arg digest "$EXPECTED_DIGEST" --arg run "$GITHUB_RUN_ID" \
  '.environment == "staging" and .health == "healthy" and .commit == $commit and .digest == $digest and .run == $run' \
  staging/staging.json > /dev/null
cp staging/staging.json evidence/staging.json

curl -fsSL https://github.com/openbao/openbao/releases/download/v2.4.1/bao_2.4.1_linux_amd64.deb \
  -o "$scratch/bao.deb"
printf '%s  %s\n' 599605411c617efe6855874e22e5e7bb0cef75d335afdef2f92d83c8e3aff471 "$scratch/bao.deb" | sha256sum -c
dpkg-deb -x "$scratch/bao.deb" "$scratch/bao"
bao="$scratch/bao/usr/bin/bao"
export BAO_ADDR=http://127.0.0.1:18200
export BAO_TOKEN
BAO_TOKEN="$(openssl rand -hex 32)"
cat > "$scratch/audit.hcl" <<CONFIG
audit "file" "fixture" {
  options = {
    file_path = "$scratch/audit.jsonl"
    log_raw = "false"
  }
}
CONFIG
"$bao" server -dev -config="$scratch/audit.hcl" -dev-listen-address=127.0.0.1:18200 -dev-root-token-id="$BAO_TOKEN" > "$scratch/bao.log" 2>&1 &
bao_pid=$!
curl -fsS --retry 10 --retry-connrefused "$BAO_ADDR/v1/sys/health" > /dev/null
"$bao" version > evidence/target-version.txt
"$bao" auth enable jwt > /dev/null
"$bao" secrets enable -path=target kv-v2 > /dev/null
"$bao" write auth/jwt/config oidc_discovery_url=https://token.actions.githubusercontent.com \
  bound_issuer=https://token.actions.githubusercontent.com > /dev/null
"$bao" policy write deploy - > /dev/null <<'POLICY'
path "target/data/production" {
  capabilities = ["create", "update"]
}
POLICY

audience=https://sdlc-acceptance.invalid/production
environment=production-sandbox
work_ref="$GITHUB_REPOSITORY/.github/workflows/sandbox-deployment.yml@refs/heads/main"
claims=$(jq -nc --arg repository "$GITHUB_REPOSITORY" --arg id "$GITHUB_REPOSITORY_ID" \
  --arg environment "$environment" --arg workflow "$work_ref" --arg sha "$GITHUB_SHA" \
  '{repository:$repository,repository_id:$id,environment:$environment,ref:"refs/heads/main",job_workflow_ref:$workflow,job_workflow_sha:$sha,runner_environment:"github-hosted"}')
write_role() {
  jq -nc --arg aud "$audience" --arg sub "$SANDBOX_SUBJECT" --argjson claims "$2" \
    '{role_type:"jwt",user_claim:"sub",bound_subject:$sub,bound_audiences:[$aud],bound_claims:$claims,token_policies:["deploy"],token_explicit_max_ttl:120,token_ttl:120,token_no_default_policy:true}' |
    "$bao" write "auth/jwt/role/$1" - > /dev/null
}
write_role production "$claims"
write_role other-repository "$(jq -c '.repository = "fixture/other-repository"' <<< "$claims")"
write_role other-environment "$(jq -c '.environment = "staging"' <<< "$claims")"
write_role other-workflow "$(jq -c --arg workflow "${work_ref/sandbox-deployment/promotion-sandbox}" '.job_workflow_ref = $workflow' <<< "$claims")"
write_role other-workflow-version "$(jq -c '.job_workflow_sha = "0000000000000000000000000000000000000000"' <<< "$claims")"

request_token() {
  curl -fsS -G --data-urlencode "audience=$1" \
    -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL" |
    jq -er .value > "$2"
}
login() {
  jq -n --rawfile jwt "$2" --arg role "$1" '{role:$role,jwt:($jwt | rtrimstr("\n"))}' |
    curl -sS -o "$3" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "$BAO_ADDR/v1/auth/jwt/login"
}
request_token "$audience" "$scratch/github.jwt"
request_token https://sdlc-acceptance.invalid/staging "$scratch/wrong-audience.jwt"
status=$(login production "$scratch/github.jwt" "$scratch/login.json")
if [[ "$status" != 200 ]]; then jq -c .errors "$scratch/login.json" >&2; exit 1; fi
jq -e '.auth.lease_duration > 0 and .auth.lease_duration <= 120 and .auth.policies == ["deploy"]' "$scratch/login.json" > /dev/null
jq '{status:200,temporary_credential_ttl:.auth.lease_duration,policies:.auth.policies}' "$scratch/login.json" > evidence/oidc-allowed.json
deny_login() {
  local label="$1" role="$2" token="$3" denied
  denied=$(login "$role" "$token" "$scratch/denied.json")
  [[ "$denied" == 400 || "$denied" == 403 ]]
  jq --argjson http "$denied" '{status:$http,errors}' "$scratch/denied.json" > "evidence/$label.json"
}
deny_login wrong-audience production "$scratch/wrong-audience.jwt"
for label in other-repository other-environment other-workflow other-workflow-version; do
  deny_login "$label" "$label" "$scratch/github.jwt"
done

deployment_token="$(jq -er .auth.client_token "$scratch/login.json")"
for path in staging unrelated; do
  status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "X-Vault-Token: $deployment_token" \
    -H 'Content-Type: application/json' -d '{"data":{"attempt":"out-of-scope"}}' "$BAO_ADDR/v1/target/data/$path")"
  [[ "$status" == 403 ]]
  jq -n --arg path "$path" '{path:$path,status:403}' > "evidence/denied-write-$path.json"
done
jq -n --arg commit "$GITHUB_SHA" --arg digest "$EXPECTED_DIGEST" \
  '{data:{commit:$commit,digest:$digest}}' > "$scratch/deployment.json"
curl -fsS -H "X-Vault-Token: $deployment_token" -H 'Content-Type: application/json' \
  --data-binary "@$scratch/deployment.json" "$BAO_ADDR/v1/target/data/production" |
  jq -e '{version:.data.version}' > evidence/target-write.json
"$bao" kv get -format=json -mount=target production | jq -e .data.data > evidence/target-state.json
jq -e --arg commit "$GITHUB_SHA" --arg digest "$EXPECTED_DIGEST" \
  '.commit == $commit and .digest == $digest' evidence/target-state.json > /dev/null
printf '%s  %s\n' "$(jq -er .digest evidence/target-state.json)" "$artifact" | sha256sum -c
mkdir "$scratch/promoted"
tar -xf "$artifact" -C "$scratch/promoted" src/service.py
HOST=127.0.0.1 PORT=18782 python3 "$scratch/promoted/src/service.py" > "$scratch/production.log" 2>&1 &
production_pid=$!
[[ "$(curl -fsS --retry 8 --retry-connrefused http://127.0.0.1:18782/health)" == healthy ]]
jq '. + {environment:"production-sandbox",health:"healthy"}' evidence/target-state.json > evidence/production.json

jq -s 'map(select(.type == "response" and
  (.request.path == "auth/jwt/login" or (.request.path | startswith("target/data/"))))
  | {time,path:.request.path,operation:.request.operation,policies:.auth.policies})' \
  "$scratch/audit.jsonl" > evidence/audit.json
jq -e 'any(.[]; .path == "target/data/production" and .policies == ["deploy"])' evidence/audit.json > /dev/null

jq -nc --arg sha "$GITHUB_SHA" --arg digest "$EXPECTED_DIGEST" --arg repository "$GITHUB_REPOSITORY" \
  --arg run "$GITHUB_RUN_ID" --arg signer "$signer" --arg issuer https://token.actions.githubusercontent.com \
  --argjson claims "$claims" \
  '{commit:$sha,digest:$digest,repository:$repository,actions_run:$run,signer:$signer,oidc_issuer:$issuer,required_claims:$claims}' > evidence/run.json
