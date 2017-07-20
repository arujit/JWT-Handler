package jwtmodule

import (
	"crypto/rsa"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	_ "os"
	_ "reflect"
)

const (
	privateKeyPath = "/home/jamesbondu/Desktop/developer-hub/Gogo/src/github.com/arujit/jwt/keys/private_key.pem"
	publicKeyPath  = "/home/jamesbondu/Desktop/developer-hub/Gogo/src/github.com/arujit/jwt/keys/public_key.pem"
)

type Keys struct {
	public  *rsa.PublicKey
	private *rsa.PrivateKey
}

var JWTMngr *Keys

func Initialize(path_params ...string) error {
	var err error
	var public_path, private_path string
	var public, private []byte
	var public_key *rsa.PublicKey
	var private_key *rsa.PrivateKey

	if len(path_params) == 2 {
		public_path = path_params[0]
		private_path = path_params[1]
	} else {
		public_path = publicKeyPath
		private_path = privateKeyPath
	}
	private, err = ioutil.ReadFile(private_path)
	if err != nil {
		log.Fatal("Error reading private key")
		return err
	}

	private_key, _ = jwt.ParseRSAPrivateKeyFromPEM(private)
	public, err = ioutil.ReadFile(public_path)

	if err != nil {
		log.Fatal("Error reading public key")
		return err
	}

	public_key, _ = jwt.ParseRSAPublicKeyFromPEM(public)
	JWTMngr = &Keys{public: public_key, private: private_key}

	return err
}

func Encode(claims map[string]interface{}) (string, error) {

	claims_token := jwt.MapClaims(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims_token)

	tokenString, err := token.SignedString(JWTMngr.private)
	if err != nil {
		log.Fatal("Error in Encoding claim")
	}
	return tokenString, err

}

func Decode(tokenString string) (map[string]interface{}, error) {
	var final_claims map[string]interface{}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return JWTMngr.public, nil

	})

	claims, _ := token.Claims.(jwt.MapClaims)

	final_claims = nil
	if token.Valid {
		err = nil
		final_claims = map[string]interface{}(claims)
	} else {
		err = fmt.Errorf("Not valid token")

	}
	return final_claims, err
}

