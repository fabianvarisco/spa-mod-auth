FROM openresty/openresty:alpine-fat

EXPOSE 8000

RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-reqargs
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-http
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-session
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-openssl
RUN /usr/local/openresty/luajit/bin/luarocks install xml2lua

# Tips: replace module por improve log
# docker exec -ti app cat /usr/local/openresty/luajit/share/lua/5.1/resty/openssl/pkey.lua > pkey.lua
# some change in pkey.lua source
# COPY ./fix/pkey.lua /usr/local/openresty/luajit/share/lua/5.1/resty/openssl/pkey.lua

# ADD  nginx.conf     /usr/local/openresty/nginx/conf/nginx.conf
