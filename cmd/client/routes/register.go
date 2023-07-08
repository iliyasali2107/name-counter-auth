package routes

import (
	"context"
	"net/http"

	"name-counter-auth/pkg/pb"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegisterRequestBody struct {
	Name     string `json:"name" binding:"required,alpha,min=3"`
	Surname  string `json:"surname" binding:"required,alpha,min=3"`
	Password string `json:"password" binding:"required,alphanum,min=8"`
}

func Register(ctx *gin.Context, c pb.AuthServiceClient) {
	var req RegisterRequestBody

	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid credentials"})
		return
	}

	res, err := c.Register(context.Background(), &pb.RegisterRequest{
		Name:     req.Name,
		Surname:  req.Surname,
		Password: req.Password,
	})
	if err != nil {
		status, _ := status.FromError(err)
		if status.Code() == codes.AlreadyExists {
			ctx.JSON(http.StatusConflict, "user already exists")
			return
		}

		ctx.JSON(http.StatusInternalServerError, "something unexpected happened")
		return
	}

	ctx.JSON(http.StatusCreated, &res)
}
