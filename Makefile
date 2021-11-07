up:
	docker-compose up -d

restart:
	docker-compose restart -t 5

runtest:
	./test/test.sh

logs:
	docker exec -it nginx-proxy tail -1000 -f /usr/local/openresty/nginx/error.log

logs-bff:
	docker exec -it bff tail -1000 -f /usr/local/openresty/nginx/error.log

get:
	curl -i localhost:8000/json

post:
	curl -H "Content-Type: application/json" -X POST -d '{"id": 1, "username":"xyz","pass":"foobar"}' localhost:8000/json

post-invalid:
	curl -H "Content-Type: application/json" -X POST -d '{"id": 1, "username":"xyz","pass:}' localhost:8000/json
