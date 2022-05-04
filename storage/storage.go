package storage

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/config"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4/pgxpool"
	"log"
	"strings"
	"time"
)

type Storage interface {
	Register(login string, password string) error
	InsertAuth(login string, userID string) error
	CheckLogin(login string, password string) error
	GetAuth(userID string) (login string, err error)
	InsertOrder(orderID string, status string, accrual float32, login string) error
	GetLoginByOrderID(orderID string) (string, error)
	RecountBalanceForLogin(login string) error
	GetAllOrdersOfUser(login string) ([]OrderInfo, error)
	GetBalanceByLogin(login string) (BalanceInfo, error)
	AddWithdrawRecord(login string, orderID string, sum float32) error
	GetAllWithdrawalsOfUser(login string) ([]WithdrawInfo, error)
}

type DatabaseInstance struct {
	conn       *pgxpool.Pool
	connConfig string
	db         *sql.DB
}

type OrderInfo struct {
	Number     string  `json:"number"`
	Status     string  `json:"status"`
	Accrual    float32 `json:"accrual"`
	UploadedAt string  `json:"uploaded_at"`
}

type WithdrawInfo struct {
	Order       string  `json:"order"`
	Sum         float32 `json:"sum"`
	ProcessedAt string  `json:"processed_at"`
}

type BalanceInfo struct {
	Current   float32 `json:"current"`
	Withdrawn float32 `json:"withdrawn"`
}

var (
	ErrLoginIsTaken           = errors.New("login is taken")
	ErrInvalidLoginOrPassword = errors.New("login or password is invalid")
)

func NewStorage(env config.Env) (Storage, error) {

	if len(env.DSNString) > 0 {
		storage, err := newDatabaseConnection(env.DSNString)
		if err != nil {
			log.Fatal(err)
		}
		storage.initStorage()
		return storage, nil
	}
	var err = errors.New("no dsn string passed")
	return nil, err
}

func newDatabaseConnection(dsn string) (*DatabaseInstance, error) {
	conn, err := pgxpool.Connect(context.Background(), dsn)
	//conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		log.Fatal(err)
	}

	//defer conn.Close(context.Background())
	log.Println("DB Connected!")
	return &DatabaseInstance{
		conn:       conn,
		connConfig: dsn,
	}, nil
}

func (db *DatabaseInstance) initStorage() {
	var cnt int

	_, err := db.conn.Exec(context.Background(), "CREATE SCHEMA IF NOT EXISTS market AUTHORIZATION postgres;")
	if err != nil {
		log.Fatal(err)
	}
	err = db.conn.QueryRow(context.Background(), "SELECT COUNT(*) FROM market.users;").Scan(&cnt)
	if err != nil {
		_, err = db.conn.Exec(context.Background(), "CREATE TABLE market.users (login VARCHAR(256) PRIMARY KEY,"+
			" password VARCHAR(256));")
		if err != nil {
			log.Fatal(err)
		}
	}
	err = db.conn.QueryRow(context.Background(), "SELECT COUNT(*) FROM market.authentication;").Scan(&cnt)
	if err != nil {
		_, err = db.conn.Exec(context.Background(), "CREATE TABLE market.authentication (login VARCHAR(256) PRIMARY KEY,"+
			" cookie VARCHAR(256));")
		if err != nil {
			log.Fatal(err)
		}
	}
	err = db.conn.QueryRow(context.Background(), "SELECT COUNT(*) FROM market.orders;").Scan(&cnt)
	if err != nil {
		_, err = db.conn.Exec(context.Background(), "CREATE TABLE market.orders (orderID VARCHAR(256) PRIMARY KEY,"+
			" status VARCHAR(256), accrual decimal, login VARCHAR(256), uploadDateTime TIMESTAMP WITH TIME ZONE );")
		if err != nil {
			log.Fatal(err)
		}
	}
	err = db.conn.QueryRow(context.Background(), "SELECT COUNT(*) FROM market.balance;").Scan(&cnt)
	if err != nil {
		_, err = db.conn.Exec(context.Background(), "CREATE TABLE market.balance (login VARCHAR(256) PRIMARY KEY,"+
			" balance decimal, withdrawn decimal);")
		if err != nil {
			log.Fatal(err)
		}
	}
	err = db.conn.QueryRow(context.Background(), "SELECT COUNT(*) FROM market.withdrawals;").Scan(&cnt)
	if err != nil {
		_, err = db.conn.Exec(context.Background(), "CREATE TABLE market.withdrawals (login VARCHAR(256), "+
			" orderID VARCHAR(256) PRIMARY KEY, sum decimal, "+
			"processedDateTime TIMESTAMP WITH TIME ZONE);")
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (db *DatabaseInstance) Register(login string, password string) error {
	ctx := context.Background()

	_, err := db.conn.Exec(ctx, "INSERT INTO market.users (login, password) VALUES ($1, $2);", login, password)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Code)
			if pgErr.Code == "23505" {
				return ErrLoginIsTaken
			} else {
				return err
			}
		}
	}
	return nil
}

func (db *DatabaseInstance) InsertAuth(login string, userID string) error {
	ctx := context.Background()

	_, err := db.conn.Exec(ctx, "INSERT INTO market.authentication (login, cookie) VALUES ($1, $2)"+
		"ON CONFLICT (login) DO UPDATE SET cookie = excluded.cookie;", login, userID)
	if err != nil {
		return err
	}
	return nil
}

func (db *DatabaseInstance) CheckLogin(login string, password string) error {
	ctx := context.Background()
	var cnt int
	err := db.conn.QueryRow(ctx, "SELECT COUNT(*) FROM market.users where login = $1 and password = $2;",
		login, password).Scan(&cnt)
	if err != nil {
		return err
	}
	if cnt != 1 {
		return ErrInvalidLoginOrPassword
	}
	return nil
}

func (db *DatabaseInstance) GetAuth(userID string) (login string, err error) {
	ctx := context.Background()
	var loginRes string
	err = db.conn.QueryRow(ctx, "SELECT login FROM market.authentication where cookie = $1;",
		userID).Scan(&loginRes)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	return loginRes, nil
}

func (db *DatabaseInstance) InsertOrder(orderID string, status string, accrual float32, login string) error {
	ctx := context.Background()

	_, err := db.conn.Exec(ctx, "INSERT INTO market.orders (orderID, status , accrual, login , uploadDateTime) "+
		"VALUES ($1, $2, $3, $4, $5) ON CONFLICT (orderID) DO UPDATE SET status = excluded.status, "+
		"accrual = excluded.accrual;",
		orderID, status, accrual, login, time.Now())
	if err != nil {
		return err
	}
	return nil
}

func (db *DatabaseInstance) GetLoginByOrderID(orderID string) (string, error) {
	ctx := context.Background()
	var login string

	err := db.conn.QueryRow(ctx, "SELECT login FROM market.orders where orderID = $1;",
		orderID).Scan(&login)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if len(login) != 0 {
		return login, nil
	}
	return "", nil
}

func (db *DatabaseInstance) RecountBalanceForLogin(login string) error {
	ctx := context.Background()
	var sum float32
	var withdrawSum float32 = 0
	err := db.conn.QueryRow(ctx, "SELECT sum(accrual) FROM market.orders where login = $1;",
		login).Scan(&sum)
	if err != nil && !strings.Contains(err.Error(), "can't scan into dest") {
		return err
	}

	err = db.conn.QueryRow(ctx, "SELECT sum(sum) FROM market.withdrawals where login = $1;",
		login).Scan(&withdrawSum)
	if err != nil && !strings.Contains(err.Error(), "can't scan into dest") {
		log.Println()
		return err
	}

	sum = sum - withdrawSum

	_, err = db.conn.Exec(ctx, "INSERT INTO market.balance (login, balance, withdrawn) "+
		"VALUES ($1, $2, $3) ON CONFLICT (login) DO UPDATE SET balance = excluded.balance,"+
		"  withdrawn = excluded.withdrawn;",
		login, sum, withdrawSum)
	if err != nil {
		return err
	}

	return nil
}

func (db *DatabaseInstance) GetAllOrdersOfUser(login string) ([]OrderInfo, error) {
	ctx := context.Background()
	var results []OrderInfo
	rows, err := db.conn.Query(ctx, "SELECT orderID, status, accrual, uploadDateTime "+
		"FROM market.orders WHERE login = $1", login)
	if err != nil {
		return nil, err
	}
	i := 0
	for rows.Next() {
		var timeFromRow time.Time
		var accrual float32
		var number string
		var status string
		err := rows.Scan(&number, &status, &accrual, &timeFromRow)
		if err != nil {
			continue
		}
		results = append(results, OrderInfo{Number: number, Status: status})
		if accrual != 0 {
			results[i].Accrual = accrual
		}
		results[i].UploadedAt = timeFromRow.Format(time.RFC3339)

		i++
	}
	return results, nil
}

func (db *DatabaseInstance) GetBalanceByLogin(login string) (BalanceInfo, error) {
	ctx := context.Background()
	var result BalanceInfo
	rows, err := db.conn.Query(ctx, "SELECT balance, withdrawn "+
		"FROM market.balance WHERE login = $1", login)
	if err != nil {
		return result, err
	}

	for rows.Next() {
		err := rows.Scan(&result.Current, &result.Withdrawn)
		if err != nil {
			return result, err
		}
	}
	return result, nil

}

func (db *DatabaseInstance) AddWithdrawRecord(login string, orderID string, sum float32) error {
	ctx := context.Background()
	_, err := db.conn.Exec(ctx, "INSERT INTO market.withdrawals (login, orderID, sum , processedDateTime) "+
		"VALUES ($1, $2, $3, $4) ON CONFLICT (orderID) DO UPDATE SET sum = excluded.sum, "+
		"processedDateTime = excluded.processedDateTime;",
		login, orderID, sum, time.Now())
	if err != nil {
		return err
	}
	return nil
}

func (db *DatabaseInstance) GetAllWithdrawalsOfUser(login string) ([]WithdrawInfo, error) {
	ctx := context.Background()
	var results []WithdrawInfo
	rows, err := db.conn.Query(ctx, "SELECT orderID, sum, processedDateTime "+
		"FROM market.withdrawals WHERE login = $1", login)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var timeFromRow time.Time
		var sum float32
		var orderID string
		err := rows.Scan(&orderID, &sum, &timeFromRow)
		if err != nil {
			continue
		}
		results = append(results, WithdrawInfo{Order: orderID, Sum: sum, ProcessedAt: timeFromRow.Format(time.RFC3339)})

	}
	return results, nil
}
