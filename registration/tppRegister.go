package registration

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"time"
)

func CreateRegistration(qsealcKey jwk.Key, softwareStatementJwt string) (string, error) {
	token, err := jwt.NewBuilder().JwtID("capybara").Expiration(time.Now().Add(time.Hour * 2)).IssuedAt(time.Now()).Build()
	if err != nil {
		return "", err
	}

	token.Set("aud", "https://op.fi/")
	token.Set("redirect_uris", []string{"https://localhost:8080/callback"})
	token.Set("grant_types", []string{"client_credentials", "authorization_code", "refresh_token"})
	token.Set("software_statement", softwareStatementJwt)

	signedKey, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, qsealcKey))
	if err != nil {
		return "", err
	}

	return string(signedKey), nil
}

type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	Type  string `json:"type"`
}

func CreateSoftwareStatementJwt(qsealcKey jwk.Key, tppId string) (string, error) {
	token, err := jwt.NewBuilder().JwtID("capybara-random-id").Expiration(time.Now().Add(time.Hour * 2)).IssuedAt(time.Now()).Issuer(tppId).Build()
	if err != nil {
		return "", err
	}

	id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	jwksEndpoint := fmt.Sprintf("https://psd2-sandbox-prod-public-tpp-jwks-store.s3.eu-central-1.amazonaws.com/%s/public-jwks.json", tppId)

	token.Set("software_client_id", id.String())
	token.Set("software_client_name", "Capybara-Vehje")
	token.Set("software_client_uri", "example.dev")
	token.Set("software_jwks_endpoint", jwksEndpoint)
	token.Set("software_jwks_revoked_endpoint", jwksEndpoint)
	token.Set("software_redirect_uris", []string{"https://localhost:8080/callback"})
	token.Set("software_roles", []string{"AISP"})
	token.Set("org_id", tppId)
	token.Set("org_name", "Capybara OY")
	token.Set("org_contacts", []Contact{
		{
			Name:  "Orava",
			Email: "orava@capybara.fi",
			Phone: "040123456789",
			Type:  "Tech Wizard",
		},
	})

	signedKey, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, qsealcKey))
	if err != nil {
		return "", err
	}

	return string(signedKey), nil
}
