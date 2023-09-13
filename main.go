package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/cloudfront/sign"
	"time"
)

const (
	privateKeyString = `-----BEGIN RSA PRIVATE KEY-----
xxxxxxxxxxxxxxxxxxx-----END RSA PRIVATE KEY-----`
	keyPairID = "999999999999999"
	url       = "https://xxxxxxxxxxxx/xxxxxxx/*"
)

func main() {
	lambda.Start(handler)
}

// handler lambda handler.
func handler() {
	// convert to rsa.PrivateKey
	block, _ := pem.Decode([]byte(privateKeyString))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse private key: %v\n", err)
		return
	}

	// create cookie signer
	signer := sign.NewCookieSigner(keyPairID, privateKey)

	// create policy
	policy := &sign.Policy{
		Statements: []sign.Statement{
			{
				Resource: url,
				Condition: sign.Condition{
					DateLessThan: &sign.AWSEpochTime{
						Time: time.Now().Add(24 * time.Hour),
					},
				},
			},
		},
	}

	// create signed cookie
	signedCookie, err := signer.SignWithPolicy(policy)
	if err != nil {
		fmt.Printf("failed to create signed cookie: %v\n", err)
		return
	}

	// output cookies
	for _, c := range signedCookie {
		fmt.Printf("cookie: %s\n", c)
	}
}
