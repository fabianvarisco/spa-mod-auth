#!/bin/bash

sso_xml="$(cat ./resources/sso.test.xml)"
readonly sso_xml

gen_time=$(date +%s)
readonly gen_time

exp_time=$(( gen_time + 60 ))
readonly exp_time

sso_xml_b64=$(echo "${sso_xml}" | \
              sed "s/{{GEN_TIME}}/${gen_time}/" | \
              sed "s/{{EXP_TIME}}/${exp_time}/" | \
              base64 -w 0 | sed 's/+/-/g' | tr -d '=')
readonly sso_xml_b64

data="foo=foo&bar=bar&token=${sso_xml_b64}&sign=XXXXX"
readonly data

set -x
curl -i --data "${data}" localhost:8000/login
