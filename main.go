package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/TylerBrock/colorjson"
	"github.com/dgrijalva/jwt-go"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
)

type publicCert struct {
	Kid string `json:"kid"`
	Pem string `json:"cert"`
}

type accesskeys struct {
	Keys        []interface{} `json:"keys"`
	PublicCert  publicCert    `json:"public_cert"`
	PublicCerts []publicCert  `json:"public_certs"`
}

type jwtTime struct {
	Iat string `json:"iat"`
	Exp string `json:"exp"`
}

func handleTime(claims map[string]interface{}) {
	out := map[string]interface{}{}

	iat := claims["iat"].(float64)
	iatTime := time.Unix(int64(iat), 0)
	out["iat"] = fmt.Sprintf("%s -- %s", iatTime.Format(time.RFC3339), humanize.Time(iatTime))

	exp := claims["exp"].(float64)
	expTime := time.Unix(int64(exp), 0)
	out["exp"] = fmt.Sprintf("%s -- %s", expTime.Format(time.RFC3339), humanize.Time(expTime))

	fmt.Println()
	prettyPrintWithColor(out)
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

	kid := token.Header["kid"]

	accessKeys := accesskeys{}
	json.Unmarshal(buf, &accessKeys)

	for _, key := range accessKeys.PublicCerts {
		if key.Kid == kid {
			pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key.Pem))
			if err != nil {
				return nil, err
			}

			return pubKey, nil
		}
	}
	return nil, errors.New("couldn't find key")

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
	var time bool
	flag.BoolVar(&verify, "v", false, "verify the JWT")
	flag.BoolVar(&time, "t", false, "humanize the timestamps")
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

	c := convertClaims(claims)

	prettyPrintWithColor(token.Header)
	fmt.Println()
	prettyPrintWithColor(c)
	if time {
		handleTime(c)
	}

}
