package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/TylerBrock/colorjson"
	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/color"
)

type accesskeys struct {
	Keys       []interface{} `json:"keys"`
	PublicCert struct {
		Kid string `json:"kid"`
		Pem string `json:"cert"`
	} `json:"public_cert"`
}

func getToken() string {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		// data is being piped to stdin
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			return scanner.Text()
		}
	} else {
		// stdin is from a terminal
	}
	return ""
}

func getKey(token *jwt.Token) (interface{}, error) {
	claims := convertClaims(token.Claims)
	authDomain := claims["iss"].(string)
	res, err := http.Get(authDomain + "/cdn-cgi/access/certs")
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, err
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	accessKeys := accesskeys{}
	json.Unmarshal(buf, &accessKeys)

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(accessKeys.PublicCert.Pem))
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func prettyPrintNoColor(data interface{}) {
	prettyPrint, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println("failed to pretty print")
		return
	}
	fmt.Println(string(prettyPrint))
}

func prettyPrintWithColor(data interface{}) {
	f := colorjson.NewFormatter()
	f.Indent = 2
	s, _ := f.Marshal(data)
	fmt.Println(string(s))
}

func convertClaims(claims jwt.Claims) map[string]interface{} {
	t := map[string]interface{}{}
	b, _ := json.Marshal(claims)
	json.Unmarshal(b, &t)
	return t
}

func main() {
	var verify bool
	flag.BoolVar(&verify, "verify", false, "verify the JWT")
	flag.BoolVar(&verify, "v", false, "verify the JWT (shorthand)")
	flag.Parse()

	parser := jwt.Parser{}
	claims := jwt.MapClaims{}
	var token *jwt.Token
	var err error

	tokenString := getToken()

	if verify {
		token, err = parser.ParseWithClaims(tokenString, &claims, getKey)
		if token.Valid {
			color.Green("Valid token")
		} else {
			color.Red("Invalid token")
		}
	} else {

		token, _, err = parser.ParseUnverified(tokenString, &claims)
		if err != nil {
			fmt.Println("failed to parse token")
			return
		}
	}

	prettyPrintWithColor(token.Header)
	fmt.Println()
	prettyPrintWithColor(convertClaims(claims))

}
