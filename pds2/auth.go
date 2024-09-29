package pds2

import (
	"github.com/aattola/OP-go/registration"
	"github.com/imroc/req/v3"
)

type OAuthToken struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	Status      string `json:"status"`
	ExpiresIn   int    `json:"expires_in"`
}

func GetAccessToken(client *req.Client, OpAuthServer string, tpp registration.TPPRegistration) (OAuthToken, error) {
	response, err := client.R().SetFormData(map[string]string{
		"grant_type":    "client_credentials",
		"scope":         "accounts",
		"client_id":     tpp.ClientID,
		"client_secret": tpp.ClientSecret,
	}).Post(OpAuthServer + "/oauth/token")

	if err != nil {
		return OAuthToken{}, err
	}

	var res OAuthToken
	err = response.Unmarshal(&res)
	if err != nil {
		return OAuthToken{}, err
	}

	return res, nil
}
