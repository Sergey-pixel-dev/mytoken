package mytoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type Token struct {
	Raw       string                 `json:"raw"`
	Method    int                    `json:"method"`
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
}

func base64urlEncode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func base64urlDecode(encoded string) ([]byte, error) {
	decoded := strings.ReplaceAll(encoded, "-", "+")
	decoded = strings.ReplaceAll(decoded, "_", "/")

	switch len(decoded) % 4 {
	case 2:
		decoded += "=="
	case 3:
		decoded += "="
	}

	return base64.StdEncoding.DecodeString(decoded)
}

func createSignature(secret, data string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64urlEncode(h.Sum(nil))
}

func (token *Token) VerifySignature(secret string) bool {
	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return false
	}
	message := parts[0] + "." + parts[1]
	expectedSignature := createSignature(secret, message)
	return hmac.Equal([]byte(parts[2]), []byte(expectedSignature))
}

func NewToken(header map[string]interface{}, payload map[string]interface{}, key string) (*Token, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, errors.New("не удалось сериализовать заголовок")
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("не удалось сериализовать полезную нагрузку")
	}

	parts := base64urlEncode(headerJSON) + "." + base64urlEncode(payloadJSON)
	signature := createSignature(key, parts)
	parts += "." + signature

	return &Token{
		Raw:       parts,
		Method:    256,
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}, nil
}

func (token *Token) SendToken(w http.ResponseWriter) error {
	tokenJSON, err := json.Marshal(envelope{"access_token": token.Raw})
	if err != nil {
		return errors.New("не удалось сериализовать токен")
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(tokenJSON)
	return err
}

func GetToken(rawToken string) (*Token, error) {
	if rawToken == "" {
		return nil, errors.New("токен не указан")
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("некорректный токен")
	}

	headerJSON, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, errors.New("ошибка декодирования заголовка")
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("ошибка десериализации заголовка")
	}

	payloadJSON, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, errors.New("ошибка декодирования полезной нагрузки")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, errors.New("ошибка десериализации полезной нагрузки")
	}

	signature := parts[2]
	return &Token{
		Raw:       rawToken,
		Method:    256,
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}, nil
}

func (token *Token) VerifyToken(f func(payload map[string]interface{}) bool, key string) bool {
	return token.VerifySignature(key) && f(token.Payload)
}

func (token *Token) SendCookieToken(name, path string, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    token.Raw,
		Path:     path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

func GetCookieToken(cookie *http.Cookie) (*Token, error) {
	return GetToken(cookie.Value)
}
