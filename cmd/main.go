package main

import (
	"fmt"
	"log"
	"net"

	"name-counter-auth/pkg/config"
	"name-counter-auth/pkg/db"
	"name-counter-auth/pkg/pb"
	"name-counter-auth/pkg/service"
	"name-counter-auth/pkg/utils"

	"google.golang.org/grpc"
)

func main() {
	c, err := config.LoadConfig()
	if err != nil {
		log.Fatalln("Failed to config", err)
	}

	storage := db.Init(c.DBUrl)

	jwt := utils.NewJwtWrapper(c.JWTSecretKey, c.Issuer, int64(c.ExpirationHours))

	lis, err := net.Listen("tcp", c.Port)
	if err != nil {
		log.Fatalln("Failed to listening")
	}

	fmt.Println("Auth service is on: ", c.Port)

	srv := service.NewService(storage, jwt)

	grpcServer := grpc.NewServer()

	pb.RegisterAuthServiceServer(grpcServer, srv)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalln("Failed to serve: ", err)
	}
}
