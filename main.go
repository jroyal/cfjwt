package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

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

	tokenString := getToken()
	claims := jwt.MapClaims{}

	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenString, &claims)
	if err != nil {
		fmt.Println("failed to parse token")
		return
	}
	prettyPrintWithColor(token.Header)
	fmt.Println()
	prettyPrintWithColor(convertClaims(claims))

}
