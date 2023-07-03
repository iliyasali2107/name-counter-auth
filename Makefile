proto:
	cprotoc pkg/pb/*.proto --go_out=plugins=grpc:.

postgres:
	docker run -d --name my-postgres -e POSTGRES_USER=user -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=name_counter -p 5432:5432 postgres:latest

server:
	go run ./cmd/server/main.go

client:
	go run ./cmd/client/*

gen:
	protoc -I=./pkg/pb --go_out=./ --go-grpc_out=./ ./pkg/pb/*.proto

start:
	docker start my-postgres

mock_service:
	mockgen -destination=pkg/mocks/mock_service.go --build_flags=--mod=mod -package=mocks name-counter-auth/pkg/service Service