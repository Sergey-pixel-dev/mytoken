package main

import (
	"fmt"
	"mytoken"
	"net/http"
	"time"
)

func handler1(w http.ResponseWriter, r *http.Request) {
	tokenAcces := mytoken.NewToken(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"userid": "1", "exp": 1733510400},
		"haha",
	)
	tokenAcces.SendToken(w)
}

func handler2(w http.ResponseWriter, r *http.Request) {
	tokenAcces, err := mytoken.GetToken(r)
	if err != nil {
		fmt.Println(err.Error())
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
		w.Write([]byte("not good"))
	}

}

func main() {
	http.HandleFunc("/gettoken/", handler1)
	http.HandleFunc("/checktoken/", handler2)
	http.ListenAndServe("localhost:8080", nil)
}
