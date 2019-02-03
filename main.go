package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/TylerBrock/colorjson"
	"github.com/dgrijalva/jwt-go"
)

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

func prettyPrint(data interface{}) {
	// prettyPrint, err := json.MarshalIndent(data, "", "  ")
	// if err != nil {
	// 	fmt.Println("failed to pretty print")
	// 	return
	// }
	// fmt.Println(string(prettyPrint))
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

func oldStyle(token string) {
	splitToken := strings.Split(token, ".")
	if len(splitToken) != 3 {
		fmt.Println("invalid jwt")
		return
	}
	c, err := base64.StdEncoding.DecodeString(splitToken[1])
	claims := map[string]interface{}{}
	json.Unmarshal(c, &claims)
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}
	prettyPrint, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println(string(prettyPrint))
}

func main() {

	tokenString := getToken()
	claims := jwt.MapClaims{}

	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenString, &claims)
	if err != nil {
		fmt.Println("failed to parse token")
		return
	}
	prettyPrint(token.Header)
	fmt.Println()
	prettyPrint(convertClaims(claims))

}
