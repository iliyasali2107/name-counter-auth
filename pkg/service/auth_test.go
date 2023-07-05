package service_test

import (
	"context"
	"crypto/rand"
	"math/big"
	"name-counter-auth/pkg/mocks"
	"name-counter-auth/pkg/models"
	"name-counter-auth/pkg/pb"
	"name-counter-auth/pkg/service"
	"name-counter-auth/pkg/utils"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestServiceLogin(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockStorage := mocks.NewMockStorage(mockCtrl)

	randomUser := createRandomUser(t)

	jwt := utils.NewJwtWrapper("secret", "test", 1)

	service := service.NewService(mockStorage, jwt)

	req := &pb.LoginRequest{
		Name:     randomUser.Name,
		Password: "qwer1234",
	}

	testCases := []struct {
		name     string
		req      *pb.LoginRequest
		expected *pb.LoginResponse
	}{
		{
			name: "qwer",
		},
	}

	mockStorage.EXPECT().GetUser(gomock.Eq(req.Name)).Times(1).Return(randomUser, nil)

	res, err := service.Login(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, int(res.Status))
	require.NotEqual(t, res.Token, "")

}

func randomRegisterRequest() *pb.RegisterRequest {
	return &pb.RegisterRequest{
		Name:     randomUserName(),
		Password: "qwer1234",
	}
}

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
