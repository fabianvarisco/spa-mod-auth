#!/bin/bash

sso_xml="$(cat ./resources/sso.test.xml)"

readonly sso_xml

sso_xml_b64=$(echo "${sso_xml}" | base64 -w 0 | sed 's/+/-/g' | tr -d '=')
readonly sso_xml_b64

data="foo=foo&bar=bar&token=${sso_xml_b64}&sign=XXXXX"
readonly data

set -x
curl -i --data "${data}" localhost:8000/login
