package authentication

import (
	"net/http"

	"github.com/rus-sharafiev/go-rest-common/auth"
	"github.com/rus-sharafiev/go-rest-common/exception"
)

func (c *controller) getAuthUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	userId, _ := auth.Headers(r)
	if len(userId) == 0 {
		exception.Unauthorized(w)
		return
	}

	query := `
		SELECT row_to_json(row)
		FROM (
			SELECT *
			FROM users u
			WHERE u."id" = $1
		) row;
	`
	c.db.WriteJsonString(w, &query, userId)
}
