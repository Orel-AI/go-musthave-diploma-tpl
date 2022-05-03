package market

import (
	"context"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/storage"
)

type MarketService struct {
	Storage storage.Storage
}

func NewMarketService(storage storage.Storage) *MarketService {
	return &MarketService{storage}
}

func (s *MarketService) Register(login string, password string, userCookie string, ctx context.Context) error {
	err := s.Storage.Register(login, password)
	if err != nil {
		return err
	}
	return nil
}

func (s *MarketService) Authenticate(login string, userCookie string, ctx context.Context) error {
	err := s.Storage.InsertAuth(login, userCookie)
	if err != nil {
		return err
	}
	return nil
}

func (s *MarketService) Login(login string, password string, ctx context.Context) error {
	err := s.Storage.CheckLogin(login, password)
	if err != nil {
		return err
	}
	return nil
}

func (s *MarketService) CheckAuth(userId string, ctx context.Context) (login string, err error) {
	login, err = s.Storage.GetAuth(userId)
	if err != nil {
		return "", err
	}
	return login, nil
}
