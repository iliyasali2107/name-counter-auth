package db_test

import (
	"log"
	"os"
	"testing"

	"name-counter-auth/pkg/config"
	"name-counter-auth/pkg/db"

	"github.com/spf13/viper"
)

var TestStorage db.Storage

func TestMain(m *testing.M) {
	config, err := loadTestConfig()
	if err != nil {
		log.Fatal("cannot load config:", err)
	}

	TestStorage = db.Init(config.DBUrl)
	os.Exit(m.Run())
}

func loadTestConfig() (config config.Config, err error) {
	viper.AddConfigPath("../config/envs")
	viper.SetConfigName(".env")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()

	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)

	return config, nil
}
