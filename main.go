package main

import (
	"fmt"
	"github.com/aattola/OP-go/certificates"
	"github.com/aattola/OP-go/pds2"
	"github.com/aattola/OP-go/registration"
	"github.com/imroc/req/v3"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"log"
	"net/url"
	"os"
	"time"
)

const (
	OP_AUTH_SERVER = "https://psd2.mtls.sandbox.apis.op.fi"
	TPP_ID         = "OP-SANDBOX-TPP-7880024c-c248"
)

type ClientRegistration struct {
	RedirectUris      []string `json:"redirect_uris"`
	GrantTypes        []string `json:"grant_types"`
	SoftwareStatement string   `json:"software_statement"`
}

func main() {
	//TIP Press <shortcut actionId="ShowIntentionActions"/> when your caret is at the underlined or highlighted text
	// to see how GoLand suggests fixing it.
	log.Println("Moro OP go")

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	client := req.NewClient()

	file, err := os.ReadFile("privateJwks.json")
	if err != nil {
		log.Fatalln(err, "failed to read privateJwks.json")
	}

	jwks, err := jwk.Parse(file)
	if err != nil {
		log.Fatalln(err, "failed to parse privateJwks.json")
	}

	qsealcKey, success := jwks.Key(1)
	if success == false {
		log.Fatalln(err, "failed to get qsealcKey")
	}

	softwareStatementJwt, err := registration.CreateSoftwareStatementJwt(qsealcKey, TPP_ID)
	if err != nil {
		log.Fatalln(err, "failed to create software statement jwt", err)
	}

	signedKey, err := registration.CreateRegistration(qsealcKey, softwareStatementJwt)
	if err != nil {
		log.Fatalln(err, "failed to create registration", err)
	}

	qwac, success := jwks.Key(0)
	if success == false {
		log.Fatalln(err, "failed to get qwac mtls key")
	}

	certPair, err := certificates.GetMTLSCerts(qwac)
	if err != nil {
		log.Fatalln(err, "failed to GetMTLSCerts")
	}

	client.SetCerts(certPair)
	client.EnableInsecureSkipVerify() // TODO: remove this line somehow?
	client.SetTimeout(10 * time.Second)

	tpp, err := registration.RegisterTPP(client, OP_AUTH_SERVER, signedKey)
	if err != nil {
		log.Fatalln(err, "failed to register tpp")
	}

	oauthToken, err := pds2.GetAccessToken(client, OP_AUTH_SERVER, tpp)
	if err != nil {
		log.Fatalln(err, "failed to get access token")
	}

	// OK
	//
	//
	//

	//	curl -vk --key key.pem --cert client.crt https://psd2.mtls.sandbox.apis.op.fi/accounts-psd2/v1/authorizations \
	//-H 'x-api-key: 30VJGNf9QuRaLm1FL8HMgccKHyZaVPR7' \
	//-H 'Authorization: Bearer ecvAPboih8ff3xPVDFYJ' \
	//-H 'x-fapi-financial-id: test' \
	//-H 'Accept: application/json' \
	//-H 'Content-Type: application/json' \
	//-d '{"expires":"2019-03-14T11:24:13.889Z"}'

	authorizationRequest, err := pds2.RegisterAuthorizationRequest(client, OP_AUTH_SERVER, oauthToken)
	if err != nil {
		log.Fatalln(err, "failed to register authorization request")
	}

	log.Printf("%+v\n", authorizationRequest)

	authorizationRequestJwt, err := pds2.CreateAuthorizationRequest(qsealcKey, tpp.ClientID, authorizationRequest.AuthorizationID)
	if err != nil {
		log.Fatalln(err, "failed to create authorization request jwt")
	}

	log.Println(string(authorizationRequestJwt))

	log.Print("\n\n\n\n")

	log.Print("Redirect uri --------\n")

	//	https://authorize.psd2-sandbox.op.fi/oauth/authorize
	//?request=<your_JWT_string>
	//&response_type=code+id_token
	//&client_id=******
	//&scope=openid%20accounts
	scope := url.PathEscape("openid accounts")
	redirectUri := fmt.Sprintf("https://authorize.psd2-sandbox.op.fi/oauth/authorize?request=%s&response_type=code id_token&client_id=%s&scope=%s", string(authorizationRequestJwt), tpp.ClientID, scope)

	log.Println(redirectUri)

}
