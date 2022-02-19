package authik

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const version = "0.1.0"
const jwksDefaultCacheDuration = time.Hour

type Client struct {
	apiURL     string
	secretKey  string
	cachedJWKS *cachedJWKS
}

type cachedJWKS struct {
	jwks      *jwk.Set
	expiresAt time.Time
}

func New(secretKey string) (*Client, error) {
	if !strings.HasPrefix(secretKey, "authik_sk_") {
		panic(fmt.Errorf("authik: invalid secret key: '%v'", secretKey))
	}

	client := &Client{
		apiURL:     "https://api.authik.com",
		secretKey:  secretKey,
		cachedJWKS: &cachedJWKS{},
	}

	return client, nil
}

type PrivateOptions struct {
	APIURL *string
}

func PrivateNew(secretKey string, privateOptions *PrivateOptions) (*Client, error) {
	client, err := New(secretKey)
	if err != nil {
		return nil, err
	}

	if privateOptions.APIURL != nil {
		client.apiURL = *privateOptions.APIURL
	} else {
		client.apiURL = "https://api.authik.com"
	}

	return client, nil
}

func (client *Client) VerifySessionToken(token string) (*SessionToken, error) {
	// Clear cache if expired
	if client.cachedJWKS.jwks != nil && time.Now().After(client.cachedJWKS.expiresAt) {
		client.cachedJWKS = &cachedJWKS{}
	}

	// Construct JWKS
	jwks := jwk.NewSet()
	_, err := client.request(http.MethodGet, "/jwks", nil, &jwks)
	if err != nil {
		return nil, err
	}
	client.cachedJWKS = &cachedJWKS{
		jwks:      &jwks,
		expiresAt: time.Now().Add(jwksDefaultCacheDuration),
	}

	// Verify token
	payload, err := jwt.ParseString(token, jwt.WithValidate(true), jwt.WithKeySet(jwks))
	if err != nil {
		if jwt.IsValidationError(err) {
			switch {
			case errors.Is(err, jwt.ErrTokenExpired()):
				return nil, ErrSessionTokenExpired
			case errors.Is(err, jwt.ErrInvalidIssuedAt()):
				return nil, ErrSessionTokenInvalid
			case errors.Is(err, jwt.ErrTokenNotYetValid()):
				return nil, ErrSessionTokenInvalid
			default:
				return nil, fmt.Errorf("%w: %s", ErrSessionTokenInvalid, err)
			}
		}
		return nil, fmt.Errorf("%w: %s", ErrSessionTokenInvalid, err)
	}

	// This should never happen, but `payload.Get` returns an error and we need to handle it.
	sessionId, ok := payload.Get("sid")
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionTokenInvalid, "session token does not contain session ID claim")
	}

	return &SessionToken{
		UserID:    payload.Subject(),
		SessionID: sessionId.(string),
		IssuedAt:  payload.IssuedAt(),
		ExpiresAt: payload.Expiration(),
		Value:     token,
	}, nil
}

func (client *Client) VerifySessionTokenRequest(request *http.Request) (*SessionToken, error) {
	token, err := request.Cookie("authik_session_token")
	if err != nil {
		return nil, ErrSessionTokenMissing
	}

	sessionToken, err := client.VerifySessionToken(token.Value)
	if err != nil {
		return nil, err
	}

	return sessionToken, nil
}

func (client *Client) GetUser(id string) (*User, error) {
	var user User

	path := fmt.Sprintf("/users/%v", id)
	_, err := client.request(http.MethodGet, path, nil, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// request makes the API request, unmarshals the response into either an
// APIError or the provided result object, and returns the response and error.
//
// Note: we don't wrap the JSON or HTTP errors in any way, because more often
// than not it's useful for the user to just look at the underlying error in
// these cases.
func (client *Client) request(method, path string, data interface{}, result interface{}) (*http.Response, error) {
	// Construct request
	url := client.apiURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+client.secretKey)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Authik-Sdk-User-Agent", fmt.Sprintf("authik-go/%v", version))

	// Make request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, err
	}
	defer res.Body.Close()

	// Parse body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return res, err
	}

	// If response is an error, unmarshal into an APIError
	if res.StatusCode >= 400 {
		var apiError APIError
		err := json.Unmarshal(body, &apiError)
		if err != nil {
			return nil, err
		}
		return res, &apiError
	}

	// If response is successful, unmarshal into the result
	err = json.Unmarshal(body, &result)
	if err != nil {
		return res, err
	}

	return res, err
}
