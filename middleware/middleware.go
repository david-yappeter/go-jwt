package middleware

import (
	"context"
	"myapp/graph/model"
	"myapp/token"
	"net/http"
)

var userCtxKey = &contextKey{"user"}

type contextKey struct {
	user string
}

//Auth Middleware Token Check
func Auth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			autho := r.Header.Get("Authorization")

			if autho == "" {
				next.ServeHTTP(w, r)
				return
			}
			tokenBeforeClaims, err := token.ValidateToken(autho)

			if err != nil {
				http.Error(w, "Invalid Token", http.StatusForbidden)
				return
			}

			claims, ok := tokenBeforeClaims.Claims.(*token.UserClaim)
			if !ok && !tokenBeforeClaims.Valid {
				http.Error(w, "Invalid Token", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, &model.User{
				ID:       claims.ID,
				Name:     claims.Name,
				Password: claims.Password,
				Email:    claims.Email,
			})

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
			return
		})
	}
}

//ForContext finds the user from the context. REQUIRES Middleware to have run.
func ForContext(ctx context.Context) *model.User {
	raw, _ := ctx.Value(userCtxKey).(*model.User)
	return raw
}
