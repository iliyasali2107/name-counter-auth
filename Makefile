proto:
	cprotoc pkg/pb/*.proto --go_out=plugins=grpc:.

postgres:
	docker run -d --name my-postgres -e POSTGRES_USER=user -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=url_redirector -p 5432:5432 postgres:latest

server:
	go run ./cmd/main.go

client:
	go run ./cmd/client/*

gen:
	protoc -I=./pkg/pb --go_out=./ --go-grpc_out=./ ./pkg/pb/*.proto --govalidators_out=./

start:
	docker start my-postgres

mock_storage:
	mockgen -destination=pkg/mocks/mock_storage.go --build_flags=--mod=mod -package=mocks name-counter-auth/pkg/db Storage

test:
	go test -v -cover ./...