# openresty mod auth

## Features

- stateless
- validate sso from authserver (token/sign)
- build jwt
- send jwt to client on signed cookie (configurable name)
- send jwt.payload to proxied service on `X-Forwarded-User` header
- to proxied service: send other proxy standard headers and remove browser headers
- validate jwt
- renew jwt between timein and timeout (thank to Sebastian Guarino <sguarin@afip.gov.ar>)
- remove jwt cookie when logout

---

## Test

- browser (curl): `test/test.sh`
- reverse-proxy: `nginx/`
- proxied-service: `bff/`

### Steps

```
make buil
make restart
make runtest
```
---
## TODO:

- avoid forever session
- servicedata
- config ssl
- use  envsubst

---
## resources

https://github.com/ketzacoatl/explore-openresty

https://github.com/zmartzone/lua-resty-openidc/blob/master/lib/resty/openidc.lua

https://openresty.org/download/agentzh-nginx-tutorials-en.html

### if you want prove lua locally (no need for this project)

```
sudo apt install lua5.3

sudo apt-get install -y luarocks
```
