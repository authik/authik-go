package authik

import "encoding/json"

type APIError struct {
	Resource string `json:"resource"`
	Type     string `json:"type"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func (e *APIError) Error() string {
	str, _ := json.Marshal(e)
	return string(str)
}

type EmailStatus string

const (
	EmailStatusUnverified EmailStatus = "unverified"
	EmailStatusVerified   EmailStatus = "verified"
)

type EmailVerifiedViaType string

const (
	EmailVerifiedViaTypeLogin EmailVerifiedViaType = "login"
)

type Email struct {
	ID          string      `json:"id"`
	Resource    string      `json:"resource"`
	CreatedAt   string      `json:"created_at"`
	Status      EmailStatus `json:"status"`
	Address     string      `json:"address"`
	VerifiedAt  *string     `json:"verified_at"`
	VerifiedVia *struct {
		Type    EmailVerifiedViaType `json:"type"`
		LoginID *string              `json:"login_id"`
	} `json:"verified_via"`
}

type User struct {
	ID        string `json:"id"`
	Resource  string `json:"resource"`
	CreatedAt string `json:"created_at"`

	Name        *string `json:"name"`
	NameDetails *struct {
		GivenName  *string `json:"given_name"`
		FamilyName *string `json:"family_name"`
	} `json:"name_details"`
	EmailID      *string `json:"email_id"`
	Email        *Email
	EmailAddress *string `json:"email_address"`
	AvatarURL    *string `json:"avatar_url"`

	LastLoginAt *string `json:"last_login_at"`
}
