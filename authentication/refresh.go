package authentication

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rus-sharafiev/go-rest-common/exception"
	"github.com/rus-sharafiev/go-rest-common/jwt"
)

func (c *controller) refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	// Get refresh token from cookie
	refreshTokenCookie, err := r.Cookie("refresh-token")
	if err != nil {
		exception.BadRequestError(w, err)
		return
	}

	refreshToken := strings.Split(refreshTokenCookie.Value, " ")[1]

	// Validate refresh token
	claims, err := jwt.Validate(refreshToken)
	if err != nil {
		exception.UnauthorizedError(w, err)
		return
	}

	// Generate access token from JWT claims
	token, err := jwt.GenerateAccessToken(claims.UserId, claims.UserAccess)
	if err != nil {
		exception.InternalServerError(w, err)
		return
	}

	result := RefreshResult{
		AccessToken: token,
	}

	// OK response
	json.NewEncoder(w).Encode(&result)
}
