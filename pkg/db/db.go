package db

import (
	"context"
	"fmt"
	"log"

	"name-counter-auth/pkg/models"

	"github.com/jackc/pgx/v5"
)

type Storage interface {
	CreateUser(user models.User) (models.User, error)
	GetUser(name string) (models.User, error)
}

type storage struct {
	DB *pgx.Conn
}

func Init(url string) Storage {
	ctx := context.Background()

	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		log.Fatal(err)
	}

	err = conn.Ping(ctx)
	if err != nil {
		log.Fatal(err)
	}

	query := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE,
		name VARCHAR(255),
		surname VARCHAR(255),
		password VARCHAR(255)
	);`

	_, err = conn.Exec(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}

	return &storage{conn}
}

func (s *storage) GetUser(email string) (models.User, error) {
	query := "SELECT id, email, name, surname, password FROM users WHERE email = $1"

	var user models.User
	err := s.DB.QueryRow(context.Background(), query, email).Scan(&user.ID, &user.Email, &user.Name, &user.Surname, &user.Password)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (s *storage) CreateUser(user models.User) (models.User, error) {
	query := "INSERT INTO users (email, name, surname, password) VALUES ($1, $2, $3, $4) RETURNING id"

	args := []interface{}{user.Email, user.Name, user.Surname, user.Password}

	err := s.DB.QueryRow(context.Background(), query, args...).Scan(&user.ID)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}
