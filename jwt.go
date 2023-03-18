package jwt_middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type Config struct {
	Secret           string `json:"secret,omitempty"`
	PayloadHeader    string `json:"payloadHeader,omitempty"`
	AuthHeader       string `json:"authHeader,omitempty"`
	AuthHeaderPrefix string `json:"authHeaderPrefix,omitempty"`
	AuthQueryParam   string `json:"authQueryParam,omitempty"`
	AuthCookieName   string `json:"authCookieName,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWT struct {
	next           http.Handler
	name           string
	secret         string
	payloadHeader  string
	authQueryParam string
	authCookieName string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if len(config.Secret) == 0 {
		config.Secret = "SECRET"
	}
	if len(config.PayloadHeader) == 0 {
		config.PayloadHeader = "X-Jwt-Payload"
	}
	if len(config.AuthQueryParam) == 0 {
		config.AuthQueryParam = "authToken"
	}
	if len(config.AuthCookieName) == 0 {
		config.AuthCookieName = "authToken"
	}

	return &JWT{
		next:           next,
		name:           name,
		secret:         config.Secret,
		payloadHeader:  config.PayloadHeader,
		authQueryParam: config.AuthQueryParam,
		authCookieName: config.AuthCookieName,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	rawToken := j.extractTokenFromHeader(req)
	if len(rawToken) == 0 && j.authQueryParam != "" {
		rawToken = j.extractTokenFromQuery(req)
	}
	if len(rawToken) == 0 && j.authCookieName != "" {
		rawToken = j.extractTokenFromCookie(req)
	}
	if len(rawToken) == 0 {
		http.Error(res, "Token not provided", http.StatusUnauthorized)
		return
	}

	token, preprocessError := preprocessJWT(rawToken)
	if preprocessError != nil {
		http.Error(res, preprocessError.Error(), http.StatusBadRequest)
		return
	}

	verified, verificationError := verifyJWT(token, j.secret)
	if verificationError != nil {
		http.Error(res, verificationError.Error(), http.StatusUnauthorized)
		return
	}

	if verified {
		// If true decode payload
		payload, decodeErr := decodeBase64(token.payload)
		if decodeErr != nil {
			http.Error(res, decodeErr.Error(), http.StatusBadRequest)
			return
		}

		// TODO Check for outside of ASCII range characters

		// Inject header as proxypayload or configured name
		req.Header.Add(j.payloadHeader, payload)
		fmt.Println(req.Header)
		j.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	}
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

// Token Deconstructed header token
type Token struct {
	header       string
	payload      string
	verification string
}

// verifyJWT Verifies jwt token with secret
func verifyJWT(token Token, secret string) (bool, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	message := token.header + "." + token.payload
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(token.verification)
	if errDecode != nil {
		return false, errDecode
	}

	if hmac.Equal(decodedVerification, expectedMAC) {
		return true, nil
	}
	return false, nil
	// TODO Add time check to jwt verification
}

func preprocessJWT(rawToken string) (Token, error) {
	var token Token

	tokenSplit := strings.Split(rawToken, ".")

	if len(tokenSplit) != 3 {
		return token, fmt.Errorf("Invalid token")
	}

	token.header = tokenSplit[0]
	token.payload = tokenSplit[1]
	token.verification = tokenSplit[2]

	return token, nil
}

// decodeBase64 Decode base64 to string
func decodeBase64(baseString string) (string, error) {
	byte, decodeErr := base64.RawURLEncoding.DecodeString(baseString)
	if decodeErr != nil {
		return baseString, fmt.Errorf("Error decoding")
	}
	return string(byte), nil
}
