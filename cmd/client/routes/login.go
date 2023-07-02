package routes

import (
	"context"
	"name-counter-auth/pkg/pb"
	"net/http"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LoginRequestBody struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func Login(ctx *gin.Context, c pb.AuthServiceClient) {
	b := LoginRequestBody{}

	if err := ctx.BindJSON(&b); err != nil {
		ctx.JSON(http.StatusBadRequest, err)
		return
	}

	res, err := c.Login(context.Background(), &pb.LoginRequest{
		Name:     b.Name,
		Password: b.Password,
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
