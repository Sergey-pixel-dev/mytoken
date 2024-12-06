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
	Raw       string
	Method    int // 256 (sha256 пока так (
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	//Valid     bool
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

func createSignature(secret, data string) string { //data уже должны быть разделены '.'
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64urlEncode(h.Sum(nil))
}

func verifySignature(secret, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	message := parts[0] + "." + parts[1]
	expectedSignature := createSignature(secret, message)
	return parts[2] == expectedSignature
}

func NewToken(header map[string]interface{}, payload map[string]interface{}, key string) *Token {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	parts := base64urlEncode(headerJSON) + "." + base64urlEncode(payloadJSON)
	signature := createSignature(key, parts)
	parts += signature
	return &Token{
		Raw:       parts,
		Method:    256,
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}
}

func (token *Token) SendToken(w http.ResponseWriter) {
	w.Write([]byte(token.Raw))
}

func GetToken(r *http.Request) (*Token, error) {
	rawToken := r.Header.Get("Authorization")
	if rawToken == "" {
		return nil, errors.New("no token")
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("incorrect token")
	}
	headerJSON, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, errors.New("err decode header")
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("err unmarshal header")
	}

	payloadJSON, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, errors.New("err decode payload")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, errors.New("err unmarshal upload")
	}
	signature := parts[2]
	token := &Token{
		Raw:       rawToken,
		Method:    256,
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}

	return token, nil
}
