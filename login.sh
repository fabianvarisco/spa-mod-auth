#!/bin/bash

sso_xml='<sso sso_at1="sso_at1_content">
<el1 el1_at1="el1_at1_content"/>
<el2 el2_at2="el2_at2_content"/>
</sso>'

readonly sso_xml

sso_xml_b64=$(echo "${sso_xml}" | base64 -w 0)
readonly sso_xml_b64

data="foo=foo&bar=bar&token=${sso_xml_b64}&sign=XXXXX"
readonly data

set -x
curl -i --data "${data}" localhost:8000/login
