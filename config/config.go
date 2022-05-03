package config

import (
	"flag"
	"os"
)

type Env struct {
	AddressToServe       string
	BaseURL              string
	FileStoragePath      string
	DSNString            string
	SecretString         string
	CookieName           string
	AccrualSystemAddress string
}

func NewConfig() Env {
	address := flag.String("a", os.Getenv("RUN_ADDRESS"), "address to start up server")
	baseURL := flag.String("b", os.Getenv("BASE_URL"), "part of shorten link")
	filePath := flag.String("f", os.Getenv("FILE_STORAGE_PATH"), "path for storage file")
	dsnString := flag.String("d", os.Getenv("DATABASE_URI"), "dsn to connect PostgreSQL")
	secretString := flag.String("s", os.Getenv("SECRET_STRING"), "String to make cookie")
	cookieName := flag.String("c", os.Getenv("COOKIE_NAME"), "Name cookie have")
	accrualSystemAddress := flag.String("r", os.Getenv("ACCRUAL_SYSTEM_ADDRESS"), "address of system")
	flag.Parse()
	envs := Env{*address, *baseURL, *filePath,
		*dsnString, *secretString, *cookieName, *accrualSystemAddress}
	if len(envs.AddressToServe) == 0 {
		envs.AddressToServe = "localhost:8080"
	}

	if len(envs.FileStoragePath) == 0 {
		envs.FileStoragePath = "storage.txt"
	}

	if len(envs.BaseURL) == 0 {
		envs.BaseURL = "http://localhost:8080"
	}

	if len(envs.SecretString) == 0 {
		envs.SecretString = "SecretString"
	}

	if len(envs.CookieName) == 0 {
		envs.CookieName = "GofmartCookie"
	}

	if len(envs.DSNString) == 0 {
		envs.DSNString = "user=postgres password=admin host=localhost port=5432 dbname=postgres sslmode=disable"
	}

	return envs
}
