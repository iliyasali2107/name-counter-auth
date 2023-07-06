package random

import (
	"crypto/rand"
	"math/big"

	"name-counter-auth/pkg/models"
	"name-counter-auth/pkg/utils"
)

// /////////////
func RandomUserName() string {
	str := RandomString(6)
	return str
}

const alphabet = "abcdefghijklmnopqrstuvwxyz"

func RandomString(n int) string {
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

// func createRandomUser(t *testing.T) models.User {
// 	arg := models.User{
// 		Name:     randomUserName(),
// 		Surname:  randomUserName(),
// 		Password: utils.HashPassword("qwer1234"),
// 	}

// 	user, err := TestStorage.CreateUser(arg)

// 	require.NoError(t, err)
// 	require.NotEmpty(t, user)

// 	require.Equal(t, arg.Name, user.Name)
// 	require.Equal(t, arg.Surname, user.Surname)

// 	require.NotZero(t, user.ID)

// 	return user
// }

func RandomUser() models.User {
	user := models.User{
		Name:     RandomUserName(),
		Surname:  RandomUserName(),
		Password: utils.HashPassword("qwer1234"),
	}

	return user
}
