package authik

import "time"

type SessionToken struct {
	UserID    string
	SessionID string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Value     string
}
