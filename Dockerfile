#build
FROM golang:1.18 AS build

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/main.go

FROM alpine:latest
WORKDIR /app


COPY --from=build /app/main /app/main


# Copy the built Go binary from the build stage to the runtime stage

# Expose port 8080 to the outside world
EXPOSE 50052

# Set the entry point for the container
CMD ["/app/main"]