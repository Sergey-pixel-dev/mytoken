package main

import (
	"mytoken"
	"net/http"
	"time"
)

func handler1(w http.ResponseWriter, r *http.Request) {
	// Создание нового токена доступа
	tokenAcces, _ := mytoken.NewToken(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"userid": "1", "exp": time.Now().Add(time.Hour).Unix()}, // Устанавливаем время истечения на 1 час
		"haha",
	)
	tokenAcces.SendToken(w)
}

func handler2(w http.ResponseWriter, r *http.Request) {
	tokRow := r.Header.Get("Authorization")
	tokenAcces, err := mytoken.GetToken(tokRow)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	isOK := tokenAcces.VerifyToken(func(payload map[string]interface{}) bool {
		exp, ok := payload["exp"].(float64)
		if !ok {
			return false
		}
		return int64(exp) > time.Now().Unix()
	}, "haha")
	if isOK {
		w.Write([]byte("super"))
	} else {
		http.Error(w, "Token expired or invalid", http.StatusUnauthorized)
	}
}

func handler3(w http.ResponseWriter, r *http.Request) {
	// Создание нового refresh токена
	tokenRefresh, _ := mytoken.NewToken(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"userid": "1", "exp": time.Now().Add(72 * time.Hour).Unix()},
		"key",
	)
	tokenRefresh.SendCookieToken("refresh_token", "/", w)
}

func handler4(w http.ResponseWriter, r *http.Request) {
	cookieToken, err1 := r.Cookie("refresh_token")
	if err1 != nil {
		http.Error(w, "No refresh token found", http.StatusUnauthorized)
		return
	}
	tokenFromCookie, err2 := mytoken.GetCookieToken(cookieToken)
	if err2 != nil {
		http.Error(w, "Invalid refresh cookie", http.StatusUnauthorized)
		return
	}
	isOK := tokenFromCookie.VerifyToken(func(payload map[string]interface{}) bool {
		exp, ok := payload["exp"].(float64)
		if !ok {
			return false
		}
		return int64(exp) > time.Now().Unix()
	}, "key")
	if !isOK {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
	} else {
		w.Write([]byte("super"))
	}
}

func main() {
	http.HandleFunc("/gettoken/", handler1)
	http.HandleFunc("/checktoken/", handler2)
	http.HandleFunc("/getcookie/", handler3)
	http.HandleFunc("/checkcookie/", handler4)
	http.ListenAndServe("localhost:8080", nil)
}
