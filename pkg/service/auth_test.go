package service_test

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"name-counter-auth/pkg/mocks"
	"name-counter-auth/pkg/models"
	"name-counter-auth/pkg/pb"
	"name-counter-auth/pkg/service"
	"name-counter-auth/pkg/utils"
	"name-counter-auth/pkg/utils/random"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceRegister(t *testing.T) {
	req := &pb.RegisterRequest{
		Email:    random.RandomEmail(),
		Name:     random.RandomUserName(),
		Surname:  random.RandomUserName(),
		Password: random.RandomString(8),
	}

	user := models.User{
		Email:    req.Email,
		Name:     req.Name,
		Surname:  req.Surname,
		Password: utils.HashPassword(req.Password),
	}

	testCases := []struct {
		name          string
		request       *pb.RegisterRequest
		buildStubs    func(storage *mocks.MockStorage)
		checkResponse func(t *testing.T, res *pb.RegisterResponse, err error)
	}{
		{
			name:    "OK",
			request: req,
			buildStubs: func(storage *mocks.MockStorage) {
				storage.EXPECT().GetUser(gomock.Eq(req.Email)).Times(1).Return(models.User{}, fmt.Errorf("failed to get user"))
				storage.EXPECT().CreateUser(NoHashMatcher(user, req.Password)).Times(1).Return(models.User{ID: 1, Name: user.Name, Surname: user.Surname, Password: user.Password}, nil)
			},
			checkResponse: func(t *testing.T, res *pb.RegisterResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, http.StatusCreated, int(res.Status))
			},
		},
		{
			name:    "Internal",
			request: req,
			buildStubs: func(storage *mocks.MockStorage) {
				storage.EXPECT().GetUser(gomock.Eq(req.Email)).Times(1).Return(models.User{}, fmt.Errorf("failed to get user"))
				storage.EXPECT().CreateUser(NoHashMatcher(user, req.Password)).Times(1).Return(models.User{}, fmt.Errorf("failed to create user:"))
			},
			checkResponse: func(t *testing.T, res *pb.RegisterResponse, err error) {
				require.Error(t, err)
				require.Nil(t, res)

				status, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, codes.Internal, status.Code())
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := mocks.NewMockStorage(ctrl)
			tc.buildStubs(storage)

			jwt := utils.NewJwtWrapper("secret", "test", 1)

			serv := service.NewService(storage, jwt)

			res, err := serv.Register(context.Background(), tc.request)

			tc.checkResponse(t, res, err)
		})
	}
}

func TestServiceLogin(t *testing.T) {
	randomUser := random.RandomUser()

	reqOk := &pb.LoginRequest{
		Email:    randomUser.Email,
		Password: "qwer1234",
	}

	reqInvalidPassword := &pb.LoginRequest{
		Email:    randomUser.Email,
		Password: "invalid",
	}

	reqNotFound := &pb.LoginRequest{
		Email:    "not-found@test.com",
		Password: "qwer1234",
	}

	testCases := []struct {
		name          string
		request       *pb.LoginRequest
		buildStubs    func(storage *mocks.MockStorage)
		checkResponse func(t *testing.T, res *pb.LoginResponse, err error)
	}{
		{
			name: "OK",
			request: &pb.LoginRequest{
				Email:    reqOk.Email,
				Password: reqOk.Password,
			},
			buildStubs: func(storage *mocks.MockStorage) {
				storage.EXPECT().GetUser(gomock.Eq(reqOk.Email)).Times(1).Return(randomUser, nil)
			},
			checkResponse: func(t *testing.T, res *pb.LoginResponse, err error) {
				require.Nil(t, err)
				require.NotNil(t, res)
				require.Equal(t, codes.OK, codes.Code(res.Status))
				require.Empty(t, res.Error)
			},
		},
		{
			name: "Invalid Password",
			request: &pb.LoginRequest{
				Email:    reqInvalidPassword.Email,
				Password: "incorrect",
			},
			buildStubs: func(storage *mocks.MockStorage) {
				storage.EXPECT().GetUser(gomock.Eq(reqInvalidPassword.Email)).Times(1).Return(randomUser, nil)
			},
			checkResponse: func(t *testing.T, res *pb.LoginResponse, err error) {
				require.NotNil(t, err)
				require.Nil(t, res)

				status, ok := status.FromError(err)
				require.NotEqual(t, ok, false)
				require.Equal(t, codes.Unauthenticated, status.Code())
			},
		},
		{
			name: "Not Found",
			request: &pb.LoginRequest{
				Email:    reqNotFound.Email,
				Password: reqNotFound.Password,
			},
			buildStubs: func(storage *mocks.MockStorage) {
				storage.EXPECT().GetUser(gomock.Eq(reqNotFound.Email)).Times(1).Return(models.User{}, fmt.Errorf("failed to get user"))
			},
			checkResponse: func(t *testing.T, res *pb.LoginResponse, err error) {
				require.Nil(t, res)
				require.NotNil(t, err)

				status, ok := status.FromError(err)
				require.NotEqual(t, ok, false)
				require.Equal(t, codes.NotFound, status.Code())
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := mocks.NewMockStorage(ctrl)
			tc.buildStubs(storage)

			jwt := utils.NewJwtWrapper("secret", "test", 1)

			serv := service.NewService(storage, jwt)

			res, err := serv.Login(context.Background(), tc.request)

			tc.checkResponse(t, res, err)
		})
	}
}

type noHashMatcher struct {
	arg      models.User
	password string
}

func (m noHashMatcher) Matches(x interface{}) bool {
	arg, ok := x.(models.User)
	if !ok {
		return false
	}

	correct := utils.CheckPasswordHash(m.password, arg.Password)
	if !correct {
		return false
	}
	arg.Password = m.arg.Password
	deepBool := reflect.DeepEqual(m.arg, arg)

	return deepBool
}

func (m noHashMatcher) String() string {
	return fmt.Sprintf("matches arg %v and password %v", m.arg, m.password)
}

func NoHashMatcher(arg models.User, password string) gomock.Matcher {
	return noHashMatcher{arg, password}
}
