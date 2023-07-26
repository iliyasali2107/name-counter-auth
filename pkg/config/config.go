package config

import (
	"os"
)

type Config struct {
	Port            string `mapstructure:"PORT"`
	DBUrl           string `mapstructure:"DB_URL"`
	JWTSecretKey    string `mapstructure:"JWT_SECRET_KEY"`
	Issuer          string `mapstructure:"ISSUER"`
	ExpirationHours int    `mapstructure:"EXPIRATION_HOURS"`
}

func LoadConfig() (config Config, err error) {
	config.DBUrl = os.Getenv("POSTGRES_DNS")
	if config.DBUrl == "" {
		config.DBUrl = "postgres://user:secret@localhost:5432/url_redirector"
	}
	config.JWTSecretKey = os.Getenv("JWT_SECRET_KEY")
	if config.JWTSecretKey == "" {
		config.JWTSecretKey = "not-secret-key"
	}
	config.Issuer = os.Getenv("ISSUER")
	config.Port = os.Getenv("PORT")
	if config.Port == "" {
		config.Port = ":50052"
	}

	hoursStr := os.Getenv("EXPIRATION_HOURS")
	hoursInt := Atoi(hoursStr)
	if hoursInt == 0 {
		config.ExpirationHours = 1
	}

	config.ExpirationHours = hoursInt

	return
}

func Atoi(s string) int {
	var n int
	var signNeg bool
	signed := false
	if len(s) == 0 {
		return 0
	}
	if s[0] == '-' {
		s = s[1:]
		signNeg = true
		signed = true
	} else if s[0] == '+' {
		s = s[1:]
		signNeg = false
		signed = true
	} else {
		signed = true
	}
	for _, i := range s {
		if !signed {
			if (i < '0' || i > '9') && i != '-' && i != '+' {
				return 0
			} else {
				n = n*10 + int(i-48)
			}
		} else {
			if i < '0' || i > '9' {
				return 0
			} else {
				n = n*10 + int(i-48)
			}
		}
	}
	if signNeg {
		return -1 * n
	}
	return n
}
