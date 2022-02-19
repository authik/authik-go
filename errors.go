package authik

import (
	"errors"
)

var (
	ErrSessionTokenMissing = errors.New("authik: provided request did not have a session token in its cookies")
	ErrSessionTokenExpired = errors.New("authik: session token has expired")
	ErrSessionTokenInvalid = errors.New("authik: session token is invalid")
)
