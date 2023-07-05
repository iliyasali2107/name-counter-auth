package service_test

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"

	"name-counter-auth/pkg/mocks"
	"name-counter-auth/pkg/models"
	"name-counter-auth/pkg/pb"
	"name-counter-auth/pkg/service"
	"name-counter-auth/pkg/utils"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceLogin(t *testing.T) {
	randomUser := createRandomUser(t)

	reqOk := &pb.LoginRequest{
		Name:     randomUser.Name,
		Password: "qwer1234",
	}

	reqInvalidPassword := &pb.LoginRequest{
		Name:     randomUser.Name,
		Password: "invalid",
	}

	reqNotFound := &pb.LoginRequest{
		Name:     "not-found",
		Password: "qwer1234",
	}

	testCases := []struct {
		name          string
		request       *pb.LoginRequest
		buildStubs    func(store *mocks.MockStorage)
		checkResponse func(t *testing.T, res *pb.LoginResponse, err error)
	}{
		{
			name: "OK",
			request: &pb.LoginRequest{
				Name:     reqOk.Name,
				Password: reqOk.Password,
			},
			buildStubs: func(store *mocks.MockStorage) {
				mockStorage.EXPECT().GetUser(gomock.Eq(reqOk.Name)).Times(1).Return(randomUser, nil)
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
				Name:     reqInvalidPassword.Name,
				Password: "incorrect",
			},
			buildStubs: func(store *mocks.MockStorage) {
				mockStorage.EXPECT().GetUser(gomock.Eq(reqInvalidPassword.Name)).Times(1).Return(randomUser, nil)
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
				Name:     reqNotFound.Name,
				Password: reqNotFound.Password,
			},
			buildStubs: func(store *mocks.MockStorage) {
				mockStorage.EXPECT().GetUser(gomock.Eq(reqNotFound.Name)).Times(1).Return(models.User{}, status.Errorf(codes.NotFound, "user not found"))
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

			store := mocks.NewMockStorage(ctrl)
			tc.buildStubs(store)

			jwt := utils.NewJwtWrapper("secret", "test", 1)

			serv := service.NewService(mockStorage, jwt)

			res, err := serv.Login(context.Background(), tc.request)

			tc.checkResponse(t, res, err)
		})
	}
}

// /////////////
func randomUserName() string {
	str := randomString(6)
	return str
}

const alphabet = "abcdefghijklmnopqrstuvwxyz"

func randomString(n int) string {
	// Calculate the length of the letterBytes string
	letterBytesLength := big.NewInt(int64(len(alphabet)))

	// Generate random bytes
	randomBytes := make([]byte, n)
	for i := 0; i < n; i++ {
		randomIndex, _ := rand.Int(rand.Reader, letterBytesLength)
		randomBytes[i] = alphabet[randomIndex.Int64()]
	}

	// Convert random bytes to a string
	randomString := string(randomBytes)
	return randomString
}

func createRandomUser(t *testing.T) models.User {
	arg := models.User{
		Name:     randomUserName(),
		Surname:  randomUserName(),
		Password: utils.HashPassword("qwer1234"),
	}

	user, err := TestStorage.CreateUser(arg)

	require.NoError(t, err)
	require.NotEmpty(t, user)

	require.Equal(t, arg.Name, user.Name)
	require.Equal(t, arg.Surname, user.Surname)

	require.NotZero(t, user.ID)

	return user
}

func TestServiceRegister(t *testing.T) {
	reqOk := &pb.RegisterRequest{
		Name: randomUserName(),
		Surname: randomUserName(),
		Password: randomString(8),
	}

	
}
