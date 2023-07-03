package routes

import (
	"context"
	"name-counter-auth/pkg/pb"
	"net/http"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegisterRequestBody struct {
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Password string `json:"password"`
}

func Register(ctx *gin.Context, c pb.AuthServiceClient) {
	b := RegisterRequestBody{}

	if err := ctx.BindJSON(&b); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	res, err := c.Register(context.Background(), &pb.RegisterRequest{
		Name:     b.Name,
		Surname:  b.Surname,
		Password: b.Password,
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
