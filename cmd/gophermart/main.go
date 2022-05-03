package main

import (
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/api/handler"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/config"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/service/market"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log"
	"net/http"
)

func main() {
	envs := config.NewConfig()
	store, err := storage.NewStorage(envs)
	if err != nil {
		log.Fatal(err)
	}
	service := market.NewMarketService(store)
	marketHandler := handler.NewMarketHandler(service, envs.BaseURL, envs.SecretString, envs.CookieName)
	r := chi.NewRouter()
	r.Use(marketHandler.AuthMiddleware)
	r.Use(handler.GzipMiddleware)
	r.Use(middleware.Logger)

	r.Post("/api/user/register", marketHandler.RegisterPOST)
	r.Post("/api/user/login", marketHandler.LoginPOST)

	err = http.ListenAndServe(envs.AddressToServe, r)
	if err != nil {
		log.Fatal(err)
	}
}
