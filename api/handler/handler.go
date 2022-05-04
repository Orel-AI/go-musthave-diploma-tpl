package handler

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/service/market"
	"github.com/Orel-AI/go-musthave-diploma-tpl.git/storage"
	"github.com/google/uuid"
	"github.com/theplant/luhn"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type MarketHandler struct {
	Market               *market.MarketService
	baseURL              string
	secretString         string
	cookieName           string
	accrualSystemAddress string
}

type gzipWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

type RequestAuthBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RequestWithdrawBody struct {
	OrderID string  `json:"order"`
	Sum     float32 `json:"sum"`
}

type key int

const (
	keyPrincipalID key    = iota
	AuthCookieName string = "Authentication"
)

var (
	ErrAuthIsExpired = errors.New("authentication is expired")
	ErrNoAuth        = errors.New("no auth cookie")
)

func (w gzipWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func GzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
			gzippedOutput, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = gzippedOutput
		}

		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		gzipW, err := gzip.NewWriterLevel(w, gzip.DefaultCompression)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer gzipW.Close()
		w.Header().Set("Content-Encoding", "gzip")
		next.ServeHTTP(gzipWriter{ResponseWriter: w, Writer: gzipW}, r)
	})
}

func (h *MarketHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(h.cookieName)
		log.Println("Cookie found by name: ", cookie)
		if err != nil && err != http.ErrNoCookie {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := h.decodeCookie(cookie)
		if err != nil {
			cookie, id, err = h.generateCookie()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.SetCookie(w, cookie)
		}
		log.Println("UserID: ", id)
		ctx := context.WithValue(r.Context(), keyPrincipalID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (h *MarketHandler) decodeCookie(cookie *http.Cookie) (uint64, error) {
	if cookie == nil {
		return 0, http.ErrNoCookie
	}

	data, err := hex.DecodeString(cookie.Value)
	if err != nil {
		return 0, err
	}

	id := binary.BigEndian.Uint64(data[:8])

	hm := hmac.New(sha256.New, []byte(h.secretString))
	hm.Write(data[:8])
	sign := hm.Sum(nil)
	if hmac.Equal(data[8:], sign) {
		return id, nil
	}
	return 0, http.ErrNoCookie
}

func (h *MarketHandler) generateCookie() (*http.Cookie, uint64, error) {
	id := make([]byte, 8)

	_, err := rand.Read(id)
	if err != nil {
		return nil, 0, err
	}

	hm := hmac.New(sha256.New, []byte(h.secretString))
	hm.Write(id)
	sign := hex.EncodeToString(append(id, hm.Sum(nil)...))

	return &http.Cookie{
			Name:   h.cookieName,
			Value:  sign,
			Path:   "/",
			Secure: false,
		},
		binary.BigEndian.Uint64(id),
		nil
}

func (h *MarketHandler) generateAuthCookie(w http.ResponseWriter, login string) error {
	authToken := uuid.NewString()
	expiresAt := time.Now().Add(300 * time.Second)

	err := h.Market.Authenticate(login, authToken, context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:    AuthCookieName,
		Value:   authToken,
		Path:    "/",
		Expires: expiresAt})
	return nil
}

func (h *MarketHandler) checkAuthCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie(AuthCookieName)
	if err != nil {
		return "", ErrNoAuth
	}
	if cookie.Expires.After(time.Now()) {
		return "", ErrAuthIsExpired
	}

	login, err := h.Market.CheckAuth(cookie.Value, context.Background())
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:    AuthCookieName,
		Value:   cookie.Value,
		Path:    "/",
		Expires: time.Now().Add(300 * time.Second)})

	return login, nil
}

func NewMarketHandler(s *market.MarketService, b string, secretString string, cookieName string,
	accrualSystemAddress string) *MarketHandler {
	return &MarketHandler{s, b, secretString,
		cookieName, accrualSystemAddress}
}

func MakeUserID(ctx context.Context) (userID string, ok bool) {
	userID64, ok := ctx.Value(keyPrincipalID).(uint64)
	if !ok {
		return "", false
	}
	userID = strconv.FormatUint(userID64, 10)
	return userID, true
}

func (h *MarketHandler) RegisterPOST(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, ok := MakeUserID(ctx)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("[RegisterPOST] - handler started")
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type header is not valid", http.StatusBadRequest)
		return
	}

	reqBody := RequestAuthBody{}

	err = json.Unmarshal(body, &reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println("[RegisterPOST] - request Unmarshaled login:", reqBody.Login, "pass:", reqBody.Password)
	if reqBody.Login == "" || reqBody.Password == "" {
		http.Error(w, "login or password is empty", http.StatusBadRequest)
		return
	}

	err = h.Market.Register(reqBody.Login, reqBody.Password, ctx)
	if errors.Is(err, storage.ErrLoginIsTaken) {
		http.Error(w, "login is taken", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.generateAuthCookie(w, reqBody.Login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	log.Println("[RegisterPOST] - end")
}

func (h *MarketHandler) LoginPOST(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type header is not valid", http.StatusBadRequest)
		return
	}

	reqBody := RequestAuthBody{}

	err = json.Unmarshal(body, &reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if reqBody.Login == "" || reqBody.Password == "" {
		http.Error(w, "login or password is empty", http.StatusBadRequest)
		return
	}

	err = h.Market.Login(reqBody.Login, reqBody.Password, ctx)
	if errors.Is(err, storage.ErrInvalidLoginOrPassword) {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.generateAuthCookie(w, reqBody.Login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *MarketHandler) OrdersPOST(w http.ResponseWriter, r *http.Request) {

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "text/plain" {
		http.Error(w, "Content-Type header is not valid", http.StatusBadRequest)
		return
	}
	if string(body) == "" {
		http.Error(w, "order is not provided", http.StatusBadRequest)
		return
	}

	login, err := h.checkAuthCookie(w, r)
	if login == "" && errors.Is(err, ErrNoAuth) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.Market.UploadOrderInfo(string(body), "NEW", 0, login, true)

	if errors.Is(err, market.ErrOrderIDIsInvalid) {
		http.Error(w, "orderID is invalid", http.StatusUnprocessableEntity)
		return
	} else if errors.Is(err, market.ErrAnotherLogin) {
		http.Error(w, "orderID uploaded by another user", http.StatusConflict)
		return
	} else if errors.Is(err, market.ErrOrderExists) {
		w.WriteHeader(http.StatusOK)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go func() {
		h.Market.GetActualizedOrderInfo(h.accrualSystemAddress, string(body), login)
	}()

	w.WriteHeader(http.StatusAccepted)
}

func (h *MarketHandler) OrdersGET(w http.ResponseWriter, r *http.Request) {

	login, err := h.checkAuthCookie(w, r)
	if login == "" && errors.Is(err, ErrNoAuth) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := h.Market.GetUserOrders(login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sort.Slice(result[:], func(i, j int) bool {
		return result[i].UploadedAt < result[j].UploadedAt
	})

	resJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(resJSON))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (h *MarketHandler) BalanceGET(w http.ResponseWriter, r *http.Request) {

	login, err := h.checkAuthCookie(w, r)
	if login == "" && errors.Is(err, ErrNoAuth) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := h.Market.GetUserBalance(login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if (storage.BalanceInfo{}) == result {
		result.Withdrawn = 0
		result.Current = 0
	}

	resJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(resJSON))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (h *MarketHandler) WithdrawPOST(w http.ResponseWriter, r *http.Request) {
	login, err := h.checkAuthCookie(w, r)
	if login == "" && errors.Is(err, ErrNoAuth) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type header is not valid", http.StatusBadRequest)
		return
	}

	reqBody := RequestWithdrawBody{}

	err = json.Unmarshal(body, &reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	orderIDInt, err := strconv.Atoi(reqBody.OrderID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !(luhn.Valid(orderIDInt)) {
		http.Error(w, market.ErrOrderIDIsInvalid.Error(), http.StatusUnprocessableEntity)
		return
	}

	err = h.Market.WithdrawBonuses(login, reqBody.OrderID, reqBody.Sum)
	if errors.Is(err, market.ErrNotEnoughBonuses) {
		http.Error(w, err.Error(), http.StatusPaymentRequired)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

}

func (h *MarketHandler) WithdrawalsGET(w http.ResponseWriter, r *http.Request) {
	login, err := h.checkAuthCookie(w, r)
	if login == "" && errors.Is(err, ErrNoAuth) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := h.Market.GetUserWithdrawals(login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sort.Slice(result[:], func(i, j int) bool {
		return result[i].ProcessedAt < result[j].ProcessedAt
	})

	resJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(resJSON))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

}
