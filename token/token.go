package token

import (
	"fmt"
	"os"
	"time"

	"myapp/graph/model"

	"github.com/dgrijalva/jwt-go"
	"github.com/vektah/gqlparser/gqlerror"
)

//UserClaim User Claim
type UserClaim struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

var jwtSecret = []byte(os.Getenv("SECRET"))

//CreateToken Create Token
func CreateToken(input model.User) (string, error) {
	var signingMethod = jwt.SigningMethodHS256
	var expiredTime = time.Now().AddDate(0, 1, 0).UnixNano() / int64(time.Millisecond)

	customClaim := UserClaim{
		ID:       input.ID,
		Name:     input.Name,
		Password: input.Password,
		Email:    input.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiredTime,
		},
	}

	token := jwt.NewWithClaims(signingMethod, customClaim)

	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", gqlerror.Errorf(fmt.Sprintf("%s", err))
	}

	return signedToken, nil
}

//ValidateToken Validate Token
func ValidateToken(t string) (*jwt.Token, error) {
	token, _ := jwt.ParseWithClaims(t, &UserClaim{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}

		return jwtSecret, nil
	})

	return token, nil
}
