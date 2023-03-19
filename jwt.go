package jwt_validation_middleware

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type Config struct {
	Secret         string            `json:"secret,omitempty"`
	Optional       bool              `json:"optional,omitempty"`
	PayloadHeaders map[string]string `json:"payloadHeaders,omitempty"`
	AuthQueryParam string            `json:"authQueryParam,omitempty"`
	AuthCookieName string            `json:"authCookieName,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Secret:         "SECRET",
		Optional:       false,
		AuthQueryParam: "authToken",
		AuthCookieName: "authToken",
	}
}

type JWT struct {
	next           http.Handler
	name           string
	secret         string
	optional       bool
	payloadHeaders map[string]string
	authQueryParam string
	authCookieName string
}

type Token struct {
	plaintext []byte
	payload   map[string]interface{}
	signature []byte
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &JWT{
		next:           next,
		name:           name,
		secret:         config.Secret,
		optional:       config.Optional,
		payloadHeaders: config.PayloadHeaders,
		authQueryParam: config.AuthQueryParam,
		authCookieName: config.AuthCookieName,
	}, nil
}

func (j *JWT) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	token, err := j.ExtractToken(request)
	if token == nil {
		if err != nil {
			http.Error(response, err.Error(), http.StatusInternalServerError)
			return
		}
		if j.optional == false {
			http.Error(response, "no token provided", http.StatusUnauthorized)
			return
		}
		j.next.ServeHTTP(response, request)
		return
	}

	verified, err := j.VerifyTokenSignature(token)
	if err != nil {
		http.Error(response, err.Error(), http.StatusUnauthorized)
		return
	}

	if !verified {
		http.Error(response, "invalid token signature", http.StatusUnauthorized)
		return
	}

	// Validate expiration, when provided and signature is valid
	if exp, ok := token.payload["exp"]; ok {
		if expInt, err := strconv.ParseInt(fmt.Sprint(exp), 10, 64); err != nil || expInt < time.Now().Unix() {
			http.Error(response, "token is expired", http.StatusUnauthorized)
			return
		}
	}

	// Inject header as proxypayload or configured name
	for k, v := range j.payloadHeaders {
		_, ok := token.payload[v]
		if ok {
			request.Header.Add(k, fmt.Sprint(token.payload[v]))
		}
	}

	j.next.ServeHTTP(response, request)
}

func (j *JWT) VerifyTokenSignature(token *Token) (bool, error) {
	mac := hmac.New(sha256.New, []byte(j.secret))
	mac.Write(token.plaintext)
	expectedMAC := mac.Sum(nil)

	if hmac.Equal(token.signature, expectedMAC) {
		return true, nil
	}
	return false, nil
}

func (j *JWT) ExtractToken(req *http.Request) (*Token, error) {
	rawToken := j.extractTokenFromHeader(req)
	if len(rawToken) == 0 && j.authQueryParam != "" {
		rawToken = j.extractTokenFromQuery(req)
	}
	if len(rawToken) == 0 && j.authCookieName != "" {
		rawToken = j.extractTokenFromCookie(req)
	}
	if len(rawToken) == 0 {
		return nil, nil
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	token := Token{
		plaintext: []byte(rawToken[0 : len(parts[0])+len(parts[1])+1]),
		signature: signature,
	}
	d := json.NewDecoder(bytes.NewBuffer(payload))
	d.UseNumber()
	err = d.Decode(&token.payload)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (j *JWT) extractTokenFromCookie(request *http.Request) string {
	cookie, err := request.Cookie(j.authCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (j *JWT) extractTokenFromQuery(request *http.Request) string {
	if request.URL.Query().Has(j.authQueryParam) {
		return request.URL.Query().Get(j.authQueryParam)
	}
	return ""
}

func (j *JWT) extractTokenFromHeader(request *http.Request) string {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return ""
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return auth[7:]
}
