package main

import (
	"log"

	"name-counter-auth/pkg/config"

	"github.com/gin-gonic/gin"
)

func main() {
	c, err := config.LoadConfig()
	if err != nil {
		log.Fatalln("Failed to config", err)
	}

	svc := &ServiceClient{
		Client: InitServiceClient(&c),
	}
	r := gin.Default()
	routes := r.Group("/auth")
	routes.POST("/register", svc.Register)
	routes.POST("/login", svc.Login)

	r.Run(c.ClientPort)
}
