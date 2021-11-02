#!/bin/bash

readonly AUTH_SERVER_CN="www.example.com"

readonly SERVICE_CN="fe-webapp-bff"

readonly SSO_TEST_XML="./test/sso.test.xml"

readonly EXAMPLE_PRIVATE_KEY_PEM="./test/${AUTH_SERVER_CN}.privatekey.pem"

readonly EXAMPLE_PUBLIC_KEY_PEM="./crypto-config/${AUTH_SERVER_CN}.publickey.pem"

if [[ ! -f $EXAMPLE_PRIVATE_KEY_PEM ]]; then
   echo "ERROR: file [$EXAMPLE_PRIVATE_KEY_PEM] not found !!!"
   exit 1
fi

if [[ ! -f $EXAMPLE_PUBLIC_KEY_PEM ]]; then
    openssl rsa -in "$EXAMPLE_PRIVATE_KEY_PEM" -pubout -out "$EXAMPLE_PUBLIC_KEY_PEM"
fi

if [[ ! -f $EXAMPLE_PUBLIC_KEY_PEM ]]; then
   echo "ERROR: file [$EXAMPLE_PUBLIC_KEY_PEM] not found !!!"
   exit 1
fi

rm -f ./tmp/sso.xml
rm -f ./tmp/sso.xml.base64
rm -f ./tmp/sign
rm -f ./tmp/sign.base64

gen_time=$(date +%s)
readonly gen_time

exp_time=$(( gen_time + 60 ))
readonly exp_time

sed "s/{{GEN_TIME}}/${gen_time}/" "$SSO_TEST_XML" | \
sed "s/{{EXP_TIME}}/${exp_time}/" | \
sed "s/{{AUTH_SERVER_CN}}/${AUTH_SERVER_CN}/" | \
sed "s/{{SERVICE_CN}}/${SERVICE_CN}/g" \
> ./tmp/sso.xml

openssl dgst -sha256 -sign "$EXAMPLE_PRIVATE_KEY_PEM" -out ./tmp/sign ./tmp/sso.xml

for file in sso.xml sign; do
    base64 -w 0 "./tmp/$file" | sed 's/+/-/g' | tr -d '=' > "./tmp/$file.base64"
done

data="foo=foo&bar=bar&token=$(cat ./tmp/sso.xml.base64)&sign=$(cat ./tmp/sign.base64)"
readonly data

set -x
curl -i --data "${data}" localhost:8000/login
