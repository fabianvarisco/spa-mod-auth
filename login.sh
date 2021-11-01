#!/bin/bash

readonly SSO_TEST_XML="./resources/sso.test.xml"

readonly EXAMPLE_KEY_PEM="./resources/www.example.com.key.pem"

rm -f ./tmp/sso.xml
rm -f ./tmp/sso.xml.base64
rm -f ./tmp/sign
rm -f ./tmp/sign.base64

gen_time=$(date +%s)
readonly gen_time

exp_time=$(( gen_time + 60 ))
readonly exp_time

sed "s/{{GEN_TIME}}/${gen_time}/" "$SSO_TEST_XML" | \
sed "s/{{EXP_TIME}}/${exp_time}/" > ./tmp/sso.xml

openssl dgst -sha256 -sign "$EXAMPLE_KEY_PEM" -out ./tmp/sign ./tmp/sso.xml

for file in sso.xml sign; do
    base64 -w 0 "./tmp/$file" | sed 's/+/-/g' | tr -d '=' > "./tmp/$file.base64"
done

data="foo=foo&bar=bar&token=$(cat ./tmp/sso.xml.base64)&sign=$(cat ./tmp/sign.base64)"
readonly data

set -x
curl -i --data "${data}" localhost:8000/login
