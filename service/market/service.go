package market

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/storage"
	"github.com/theplant/luhn"
	"io"
	"log"
	"net/http"
	"strconv"
)

type MarketService struct {
	Storage storage.Storage
}

type ResponseBodyOrder struct {
	OrderID string  `json:"order"`
	Status  string  `json:"status"`
	Accrual float32 `json:"accrual"`
}

var (
	ErrOrderIDIsInvalid = errors.New("orderID is invalid")
	ErrOrderExists      = errors.New("orderID is already in DB")
	ErrAnotherLogin     = errors.New("orderID is already in DB, but uploaded by another user")
)

func NewMarketService(storage storage.Storage) *MarketService {
	return &MarketService{storage}
}

func (s *MarketService) Register(login string, password string, ctx context.Context) error {
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

func (s *MarketService) CheckAuth(userID string, ctx context.Context) (login string, err error) {
	login, err = s.Storage.GetAuth(userID)
	if err != nil {
		return "", err
	}
	return login, nil
}

func (s *MarketService) UploadOrderInfo(orderID string, status string, accrual float32,
	login string, isFirstInsert bool) error {

	orderIDInt, err := strconv.Atoi(orderID)
	if err != nil {
		return ErrOrderIDIsInvalid
	}
	if !(luhn.Valid(orderIDInt)) {
		return ErrOrderIDIsInvalid
	}

	if isFirstInsert {
		res, err := s.Storage.GetLoginByOrderID(orderID)
		if err != nil {
			return err
		}
		if res != "" && res == login {
			return ErrOrderExists
		} else if res != "" && res != login {
			return ErrAnotherLogin
		}
	}

	err = s.Storage.InsertOrder(orderID, status, accrual, login)
	if err != nil {
		return err
	}
	return nil
}

func (s *MarketService) GetActualizedOrderInfo(url string, orderID string, login string) {
	log.Println("[GetActualizedOrderInfo] ", url+"/api/orders/"+orderID)
	resp, err := http.Get(url + "/api/orders/" + orderID)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("[GetActualizedOrderInfo] " + err.Error())
		return
	}
	log.Println("[GetActualizedOrderInfo] ", string(body))
	responseBody := ResponseBodyOrder{}
	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		log.Println("[GetActualizedOrderInfo] " + err.Error())
		return
	}

	err = s.UploadOrderInfo(responseBody.OrderID, responseBody.Status, responseBody.Accrual, login, false)
	if err != nil {
		log.Println("[GetActualizedOrderInfo] " + err.Error())
		return
	}

	err = s.Storage.RecountBalanceForLogin(login)
	if err != nil {
		log.Println("[GetActualizedOrderInfo] " + err.Error())
		return
	}
}

func (s *MarketService) GetUserOrders(login string) ([]storage.OrderInfo, error) {

	result, err := s.Storage.GetAllOrdersOfUser(login)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *MarketService) GetUserBalance(login string) (storage.BalanceInfo, error) {

	result, err := s.Storage.GetBalanceByLogin(login)
	if err != nil {
		return result, err
	}

	return result, nil
}
