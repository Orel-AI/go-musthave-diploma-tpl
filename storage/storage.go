package storage

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/config"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4/pgxpool"
	"log"
)

type Storage interface {
	Register(login string, password string) error
	InsertAuth(login string, userId string) error
	CheckLogin(login string, password string) error
	GetAuth(userId string) (login string, err error)
}

type DatabaseInstance struct {
	conn       *pgxpool.Pool
	connConfig string
	db         *sql.DB
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
		_, err = db.conn.Exec(context.Background(), "CREATE TABLE market.authentication (login VARCHAR(256) PRIMARY KEY,"+
			" cookie VARCHAR(256));")
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

func (db *DatabaseInstance) InsertAuth(login string, userId string) error {
	ctx := context.Background()

	_, err := db.conn.Exec(ctx, "INSERT INTO market.authentication (login, cookie) VALUES ($1, $2)"+
		"ON CONFLICT (login) DO UPDATE SET cookie = excluded.cookie;", login, userId)
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

func (db *DatabaseInstance) GetAuth(userId string) (login string, err error) {
	ctx := context.Background()
	var logins []string
	err = db.conn.QueryRow(ctx, "SELECT login FROM market.authentication where login = $1;",
		login).Scan(&logins)
	if err != nil {
		return "", err
	}
	return logins[0], nil
}
