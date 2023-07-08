package service

import (
	"context"
	"net/http"

	"name-counter-auth/pkg/db"
	"name-counter-auth/pkg/models"
	"name-counter-auth/pkg/pb"
	"name-counter-auth/pkg/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	S   db.Storage
	Jwt utils.JwtWrapper
	pb.UnimplementedAuthServiceServer
}

type Service interface {
	pb.AuthServiceServer
	Register(context.Context, *pb.RegisterRequest) (*pb.RegisterResponse, error)
	Login(context.Context, *pb.LoginRequest) (*pb.LoginResponse, error)
	Validate(context.Context, *pb.ValidateRequest) (*pb.ValidateResponse, error)
}

func NewService(s db.Storage, jwt utils.JwtWrapper) Service {
	return &service{
		S:   s,
		Jwt: jwt,
	}
}

// TODO: grpc_validator pacakage for message validations

func (srv *service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if _, err := srv.S.GetUser(req.Email); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "user already exists")
	}

	var user models.User
	user.Email = req.Email
	user.Name = req.Name
	user.Surname = req.Surname
	user.Password = utils.HashPassword(req.Password)

	user, err := srv.S.CreateUser(user)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "something unexpected happened")
	}

	// TODO: user caching (redis)
	return &pb.RegisterResponse{
		Status: http.StatusCreated,
	}, nil
}

func (srv *service) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User

	user, err := srv.S.GetUser(req.Email)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)
	if !match {
		return nil, status.Errorf(codes.Unauthenticated, "password is incorrect")
	}

	token, _ := srv.Jwt.GenerateToken(user)

	return &pb.LoginResponse{
		Status: int64(codes.OK),
		Token:  token,
	}, nil
}

func (srv *service) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := srv.Jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, err
	}

	user, err := srv.S.GetUser(claims.Name)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, err
	}

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserID: user.ID,
	}, nil
}
