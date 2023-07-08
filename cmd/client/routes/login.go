package routes

import (
	"context"
	"net/http"

	"name-counter-auth/pkg/pb"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LoginRequestBody struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,alphanum"`
}

func Login(ctx *gin.Context, c pb.AuthServiceClient) {
	var req LoginRequestBody

	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid credentials"})
		return
	}

	res, err := c.Login(context.Background(), &pb.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		status, _ := status.FromError(err)
		switch status.Code() {
		case codes.NotFound:
			ctx.JSON(http.StatusNotFound, status.Message())
		case codes.Unauthenticated:
			ctx.JSON(http.StatusUnauthorized, status.Message())
		default:
			ctx.JSON(http.StatusInternalServerError, "something unexpected occured")
		}

		return
	}

	ctx.JSON(http.StatusCreated, &res)
}
