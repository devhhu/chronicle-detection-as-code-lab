up:
	docker-compose up --build

down:
	docker-compose down

logs:
	cat processed-logs/udm_log/*.log | jq .

clean:
	rm -rf processed-logs/udm_log/*
