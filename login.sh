#!/bin/bash

readonly AUTH_SERVER_CN="www.example.com"
readonly SERVICE_CN="fe-webapp-bff"
readonly SSO_TEST_XML="./test/sso.test.xml"
readonly MY_PRIVATE_KEY_PEM="./test/myprivatekey.pem"
readonly MY_PUBLIC_KEY_PEM="./crypto-config/mypublickey.pem"
readonly AUTH_SERVER_PRIVATE_KEY_PEM="./test/${AUTH_SERVER_CN}.privatekey.pem"
readonly AUTH_SERVER_PUBLIC_KEY_PEM="./crypto-config/${AUTH_SERVER_CN}.publickey.pem"

rm -f ./crypto-config/*
rm -f ./tmp/*

if [[ ! -f $MY_PRIVATE_KEY_PEM ]]; then
   echo "ERROR: file [$MY_PRIVATE_KEY_PEM] not found !!!"
   exit 1
fi

openssl rsa -in "$MY_PRIVATE_KEY_PEM" -pubout -out "$MY_PUBLIC_KEY_PEM"

if [[ ! -f $MY_PUBLIC_KEY_PEM ]]; then
   echo "ERROR: file [$MY_PUBLIC_KEY_PEM] not found !!!"
   exit 1
fi

cp "$MY_PRIVATE_KEY_PEM" ./crypto-config/

if [[ ! -f $AUTH_SERVER_PRIVATE_KEY_PEM ]]; then
   echo "ERROR: file [$AUTH_SERVER_PRIVATE_KEY_PEM] not found !!!"
   exit 1
fi

openssl rsa -in "$AUTH_SERVER_PRIVATE_KEY_PEM" -pubout -out "$AUTH_SERVER_PUBLIC_KEY_PEM"

if [[ ! -f $AUTH_SERVER_PUBLIC_KEY_PEM ]]; then
   echo "ERROR: file [$AUTH_SERVER_PUBLIC_KEY_PEM] not found !!!"
   exit 1
fi

cp "$MY_PRIVATE_KEY_PEM" ./crypto-config/

gen_time=$(date +%s)
readonly gen_time

exp_time=$(( gen_time + 60 ))
readonly exp_time

sed "s/{{GEN_TIME}}/${gen_time}/" "$SSO_TEST_XML" | \
sed "s/{{EXP_TIME}}/${exp_time}/" | \
sed "s/{{AUTH_SERVER_CN}}/${AUTH_SERVER_CN}/" | \
sed "s/{{SERVICE_CN}}/${SERVICE_CN}/g" \
> ./tmp/sso.xml

openssl dgst -sha256 -sign "$AUTH_SERVER_PRIVATE_KEY_PEM" -out ./tmp/sign ./tmp/sso.xml

for file in sso.xml sign; do
    base64 -w 0 "./tmp/$file" | sed 's/+/-/g' | tr -d '=' > "./tmp/$file.base64"
done

data="foo=foo&bar=bar&token=$(cat ./tmp/sso.xml.base64)&sign=$(cat ./tmp/sign.base64)"
readonly data

set -x
curl -i --data "${data}" localhost:8000/login
