package authentication

import (
	"encoding/json"
	"net/http"

	"github.com/rus-sharafiev/go-rest-common/auth"
	"github.com/rus-sharafiev/go-rest-common/exception"
	"github.com/rus-sharafiev/go-rest-common/localization"
)

func (c *controller) logOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	userId, _ := auth.Headers(r)
	if len(userId) == 0 {
		exception.Unauthorized(w)
		return
	}

	// Delete session
	if fingerprint := r.Header.Get("Fingerprint"); len(fingerprint) != 0 {
		query := `DELETE FROM sessions WHERE fingerprint = $1;`
		if _, err := c.db.Query(&query, fingerprint); err != nil {
			exception.InternalServerError(w, err)
			return
		}
	}

	// Remove refresh token
	cookie := &http.Cookie{
		Name:   "refresh-token",
		Value:  "",
		Path:   "/api/auth/refresh",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)

	successMessage := Message{
		StatusCode: http.StatusOK,
		Message: localization.SelectString(r, localization.Langs{
			En: "Logged out successfully",
			Ru: "Выход из системы",
		}),
	}

	// OK response
	json.NewEncoder(w).Encode(&successMessage)
}
