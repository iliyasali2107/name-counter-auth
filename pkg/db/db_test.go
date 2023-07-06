package db_test

import (
	"testing"

	"name-counter-auth/pkg/models"
	"name-counter-auth/pkg/utils/random"

	"github.com/stretchr/testify/require"
)

func TestCreateUser(t *testing.T) {
	createRandomUser(t)
}

func TestGetUser(t *testing.T) {
	user := createRandomUser(t)

	t.Run("OK", func(t *testing.T) {
		user1, err := TestStorage.GetUser(user.Name)
		require.NoError(t, err)
		require.NotEmpty(t, user1)
		require.Equal(t, user, user1)
	})

	t.Run("InvalidUser", func(t *testing.T) {
		user2, err := TestStorage.GetUser("invalid-user-name")
		require.Error(t, err)
		require.Empty(t, user2)
	})
}

func createRandomUser(t *testing.T) models.User {
	user := random.RandomUser()

	t.Run("OK", func(t *testing.T) {
		user1, err := TestStorage.CreateUser(user)
		user.ID = user1.ID
		require.NoError(t, err)
		require.NotEmpty(t, user1)
		require.Equal(t, user, user1)
	})

	t.Run("AlreadyExists", func(t *testing.T) {
		user2, err := TestStorage.CreateUser(user)
		require.Error(t, err)
		require.Empty(t, user2)
	})

	return user
}
