package pds2

import (
	"encoding/json"
	"github.com/imroc/req/v3"
	"os"
	"time"
)

type AuthorizationsBody struct {
	Expires         string `json:"expires"` // all dates are ISO 8601 aka. RFC3339 https://ijmacd.github.io/rfc3339-iso8601/
	TransactionFrom string `json:"transactionFrom"`
	TransactionTo   string `json:"transactionTo"`
}

type AuthorizationResponse struct {
	AuthorizationsBody
	AuthorizationID string `json:"authorizationId"`
	Created         string `json:"created"`
	Modified        string `json:"modified"`
	Status          string `json:"status"`
}

func RegisterAuthorizationRequest(client *req.Client, OpAuthServer string, oauthToken OAuthToken) (AuthorizationResponse, error) {
	req := client.R()

	apiKey := os.Getenv("OP_API_KEY")

	req.SetHeader("x-api-key", apiKey)
	req.SetHeader("x-fapi-financial-id", "Capybara-Vehje")
	req.SetContentType("application/json")
	req.SetBearerAuthToken(oauthToken.AccessToken)

	body := AuthorizationsBody{
		Expires:         time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339), // 90 days from now
		TransactionFrom: time.Now().AddDate(0, 0, -700).Format(time.DateOnly),     // 700 days ago psd2 permits max 730 days
		TransactionTo:   time.Now().Add(-1 * time.Hour).Format(time.DateOnly),     // -1 hour from now for good measure
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	req.SetBody(bodyBytes)

	response, err := req.Post(OpAuthServer + "/accounts-psd2/v1/authorizations")
	if err != nil {
		return AuthorizationResponse{}, err
	}

	var authResponse AuthorizationResponse
	err = response.UnmarshalJson(&authResponse)
	if err != nil {
		return AuthorizationResponse{}, err
	}

	return authResponse, nil
}
