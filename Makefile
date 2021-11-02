build:
	docker build --tag=app:3 --rm=true ./

run:
	docker run -d --name app --net host -p 127.0.0.1:8000:8000 app:3

dev: clean
	docker run -d --name app --net host -p 127.0.0.1:8000:8000 \
	    -e INITIAL_SLACK_SECONDS=60 \
	    -e CRYPTO_CONFIG_PATH=/crypto-config/ \
		-v `pwd`/nginx/conf:/usr/local/openresty/nginx/conf/ \
		-v `pwd`/lualib/afip:/usr/local/openresty/lualib/afip/ \
		app:3

clean:
	docker stop app || true
	docker rm   app || true

reload:
	docker exec -it app /usr/local/openresty/nginx/sbin/nginx -s reload

logs:
	docker exec -it app tail -1000 -f /usr/local/openresty/nginx/error.log

get:
	curl -i localhost:8000/json

post:
	curl -H "Content-Type: application/json" -X POST -d '{"id": 1, "username":"xyz","pass":"foobar"}' localhost:8000/json

post-invalid:
	curl -H "Content-Type: application/json" -X POST -d '{"id": 1, "username":"xyz","pass:}' localhost:8000/json

login:
	curl --data 'foo=bar&bar=baz&bar=blah&sign=XXXX&token=${var_token}' localhost:8000/login
