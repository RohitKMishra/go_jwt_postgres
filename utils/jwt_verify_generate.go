package utils

import "github.com/golang-jwt/jwt/v5"

type Parser struct {
	Method          jwt.SigningMethod
	ValidateMethods []jwt.SigningMethod
}

func VerifyToken(token string) (*jwt.MapClaims, error) {
	claims := &jwt.MapClaims{}
	parser := jwt.Parse(jwt.SigningMethodHS256)
}
func NewParser(method jwt.SigningMethod) *Parser {
	return &Parser{
		Method: method,
		ValidateMethods: []jwt.SigningMethod{
			method,
		},
	}
}
