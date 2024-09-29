package registration

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/imroc/req/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"log"
	"os"
	"time"
)

func RegisterTPP(client *req.Client, OpAuthServer string, signedJWTKey string) {
	apiKey := os.Getenv("OP_CLIENT_ID")

	r := client.R().SetContentType("application/jwt")

	r.SetHeader("x-api-key", apiKey)
	r.SetBody(signedJWTKey)
	response, err := r.Post(OpAuthServer + "/tpp-registration/register")
	if err != nil {
		log.Fatalln(err, "failed to register tpp")
	}

	log.Println("status code", response.StatusCode)
	log.Println("response", response.String())

}

func CreateRegistration(qsealcKey jwk.Key, softwareStatementJwt string) (string, error) {
	jwt.Settings(jwt.WithFlattenAudience(true))
	token, err := jwt.NewBuilder().JwtID("capybara").Expiration(time.Now().Add(time.Hour * 2)).IssuedAt(time.Now()).Build()
	if err != nil {
		return "", err
	}

	token.Set("redirect_uris", []string{"https://localhost:8080/callback"})
	token.Set("grant_types", []string{"client_credentials", "authorization_code", "refresh_token"})
	token.Set("software_statement", softwareStatementJwt)
	token.Set("aud", "https://op.fi/")

	mappi, _ := token.AsMap(context.Background())

	log.Println(mappi, "token")

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
	token.Set("software_client_uri", "https://jeffe.co")
	token.Set("software_jwks_endpoint", jwksEndpoint)
	token.Set("software_jwks_revoked_endpoint", jwksEndpoint)
	token.Set("software_redirect_uris", []string{"https://localhost:8080/callback"})
	token.Set("software_roles", []string{"AIS"})
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
