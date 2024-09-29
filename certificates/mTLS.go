package certificates

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GetMTLSCerts(qwacKey jwk.Key) (tls.Certificate, error) {

	cert, success := qwacKey.X509CertChain().Get(0)
	if success == false {
		return tls.Certificate{}, errors.New("failed to get x509 cert chain")
	}

	decodeString, err := base64.StdEncoding.DecodeString(string(cert))
	if err != nil {
		return tls.Certificate{}, err
	}

	pemBuffer := new(bytes.Buffer)
	err = pem.Encode(pemBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decodeString,
	})
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pemBuffer.Bytes()

	pemType, pemBytes, err := jwk.EncodeX509(qwacKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	privateKeyPem := &pem.Block{
		Type:  pemType,
		Bytes: pemBytes,
	}

	p := pem.EncodeToMemory(privateKeyPem)

	certPair, err := tls.X509KeyPair(certPEM, p)

	if err != nil {
		return tls.Certificate{}, err
	}

	return certPair, nil
}
