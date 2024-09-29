package main

import (
	"github.com/aattola/OP-go/certificates"
	"github.com/aattola/OP-go/registration"
	"github.com/imroc/req/v3"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"log"
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

	client := req.DevMode()

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

	log.Println("signeerattu avain: ", signedKey)

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

	registration.RegisterTPP(client, OP_AUTH_SERVER, signedKey)
	//response, err := client.R().SetFormData(map[string]string{
	//	"grant_type":    "client_credentials",
	//	"scope":         "accounts",
	//	"client_id":     clientId,
	//	"client_secret": clientSecret,
	//}).Post(OP_AUTH_SERVER + "/oauth/token")
	//if err != nil {
	//
	//	log.Fatalln(err, "failed to get access token")
	//}
	//
	//log.Println("res: ", response.String())
	//log.Println("status: ", response.Status, response.StatusCode)

}
