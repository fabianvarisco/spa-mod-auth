build:
	docker build --tag=app:3 --rm=true ./

run:
	docker run -d --name app --net host -p 127.0.0.1:8000:8000 app:3

dev: clean
	docker run -d --name app --net host -p 127.0.0.1:8000:8000 \
		-v `pwd`:/usr/local/openresty/nginx/conf/ \
		-v `pwd`:/usr/local/openresty/lualib/afip/ \
		app:3

clean:
	docker stop app || true
	docker rm   app || true

reload:
	docker exec -it app /usr/local/openresty/nginx/sbin/nginx -s reload

logs:
	docker exec -it app tail -f /usr/local/openresty/nginx/error.log

get:
	curl -i localhost:8000/json

post:
	curl -H "Content-Type: application/json" -X POST -d '{"id": 1, "username":"xyz","pass":"foobar"}' localhost:8000/json

post-invalid:
	curl -H "Content-Type: application/json" -X POST -d '{"id": 1, "username":"xyz","pass:}' localhost:8000/json

sso:
	rm -f ./resources/sso.xml.b64
	echo '<sso at1="pepe"><t1><t2 at2="coco"/></t1></sso>' | base64 > ./resources/sso.xml.b64

var_token=$(echo '<sso at1="pepe"><t1><t2 at2="coco"/></t1></sso>' | base64)

login:
	curl --data 'foo=bar&bar=baz&bar=blah&sign=XXXX&token=${var_token}' localhost:8000/login

pepe:
	echo "var_token: ${var_token}"
