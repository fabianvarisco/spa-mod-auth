#!/bin/bash

set -e

BASE="$(dirname "$0")"
readonly BASE

readonly AUTH_SERVER_CN="www.example.com"
readonly SERVICE_CN="fe-webapp-bff"
readonly SSO_TEST_XML="$BASE/sso.test.xml"
readonly JWT_SECRET_TXT="$BASE/jwtsecret.txt"
readonly AUTH_SERVER_PRIVATE_KEY_PEM="$BASE/$AUTH_SERVER_CN.privatekey.pem"
readonly CRYPTO_CONFIG_DIR="$BASE/../nginx/crypto-config/"
readonly AUTH_SERVER_PUBLIC_KEY_PEM="${CRYPTO_CONFIG_DIR}${AUTH_SERVER_CN}.publickey.pem"
readonly TMP_DIR="$BASE/tmp/"

mkdir -p "$CRYPTO_CONFIG_DIR"
rm    -f "$CRYPTO_CONFIG_DIR"*

mkdir -p "$TMP_DIR"
rm    -f "$TMP_DIR"*

if [[ ! -f $JWT_SECRET_TXT ]]; then
   echo "ERROR: file [$JWT_SECRET_TXT] not found !!!"
   exit 1
fi

cp "$JWT_SECRET_TXT" "${CRYPTO_CONFIG_DIR}"

if [[ ! -f $AUTH_SERVER_PRIVATE_KEY_PEM ]]; then
   echo "ERROR: file [$AUTH_SERVER_PRIVATE_KEY_PEM] not found !!!"
   exit 1
fi

openssl rsa -in "$AUTH_SERVER_PRIVATE_KEY_PEM" -pubout -out "$AUTH_SERVER_PUBLIC_KEY_PEM"

if [[ ! -f $AUTH_SERVER_PUBLIC_KEY_PEM ]]; then
   echo "ERROR: file [$AUTH_SERVER_PUBLIC_KEY_PEM] not found !!!"
   exit 1
fi

gen_time=$(date +%s)
readonly gen_time

exp_time=$(( gen_time + 60 ))
readonly exp_time

sed "s/{{GEN_TIME}}/${gen_time}/" "$SSO_TEST_XML" | \
sed "s/{{EXP_TIME}}/${exp_time}/" | \
sed "s/{{AUTH_SERVER_CN}}/${AUTH_SERVER_CN}/" | \
sed "s/{{SERVICE_CN}}/${SERVICE_CN}/g" \
> "${TMP_DIR}sso.xml"

openssl dgst -sha256 -sign "$AUTH_SERVER_PRIVATE_KEY_PEM" -out "${TMP_DIR}sign" "${TMP_DIR}sso.xml"

for file in sso.xml sign; do
    base64 -w 0 "${TMP_DIR}$file" | sed 's/+/-/g' | tr -d '=' > "${TMP_DIR}$file.base64"
done

data="foo=foo&bar=bar&token=$(cat "${TMP_DIR}"sso.xml.base64)&sign=$(cat "${TMP_DIR}"sign.base64)"
readonly data

# curl -v -i: for more info

curl localhost:8000/nginx-hello

curl localhost:8000/api/public/hello

curl \
     --data "${data}" \
     -L \
     -c "${TMP_DIR}cookiefile" \
     localhost:8000/api/login

curl \
     --data '{"someId": 1231, "someValue": "eapp"}' \
     -c "${TMP_DIR}cookiefile" \
     -b "${TMP_DIR}cookiefile" \
     localhost:8000/api/secure

curl \
     -c "${TMP_DIR}cookiefile" \
     -b "${TMP_DIR}cookiefile" \
     localhost:8000/api/logout
