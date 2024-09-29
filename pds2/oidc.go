package pds2

import (
	"encoding/base64"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"time"
)

type JWTClaims struct {
	Userinfo Userinfo `json:"userinfo"`
	IDToken  IDToken  `json:"id_token"`
}
type AuthorizationID struct {
	Value     string `json:"value"`
	Essential bool   `json:"essential"`
}
type Userinfo struct {
	AuthorizationID AuthorizationID `json:"authorizationId"`
}
type Acr struct {
	Essential bool     `json:"essential"`
	Values    []string `json:"values"`
}
type IDToken struct {
	AuthorizationID AuthorizationID `json:"authorizationId"`
	Acr             Acr             `json:"acr"`
}

func CreateAuthorizationRequest(qsealcKey jwk.Key, clientId string, authorizationId string) ([]byte, error) {

	key := jwt.NewBuilder()
	key.Issuer(clientId)
	token, err := key.Build()
	if err != nil {
		return nil, err
	}

	token.Set("aud", "https://mtls.apis.op.fi")
	token.Set("kid", qsealcKey.KeyID())
	token.Set("alg", "RS256")
	token.Set("typ", "JWT")
	token.Set("response_type", "code id_token")
	token.Set("client_id", "test")
	token.Set("redirect_uri", "https://localhost:8080/callback")
	token.Set("scope", "openid accounts")

	state := base64.StdEncoding.EncodeToString([]byte(`{"ok": true, "author": "aattola"}`))
	token.Set("state", state)
	token.Set("nonce", "123456") // todo: generate nonce or something
	token.Set("max_age", 3600)
	token.Set("exp", time.Now().Add(time.Second*3600).Unix())
	token.Set("iat", time.Now().Unix())

	claims := JWTClaims{
		Userinfo: Userinfo{
			AuthorizationID: AuthorizationID{
				Value:     authorizationId,
				Essential: true,
			},
		},
		IDToken: IDToken{
			AuthorizationID: AuthorizationID{
				Value:     authorizationId,
				Essential: true,
			},
			Acr: Acr{
				Essential: true,
				Values:    []string{"urn:openbanking:psd2:sca"},
			},
		},
	}

	token.Set("claims", claims)

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, qsealcKey))
	if err != nil {
		return nil, err
	}

	return signedToken, nil
}
