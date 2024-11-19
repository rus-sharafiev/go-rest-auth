package auth

import (
	"net/http"

	"github.com/rus-sharafiev/go-rest-common/auth"
	"github.com/rus-sharafiev/go-rest-common/db"
	"github.com/rus-sharafiev/go-rest-common/exception"
)

type getAuthUser struct {
	db *db.Postgres
}

func (c getAuthUser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		exception.MethodNotAllowed(w)
		return
	}

	userId, _ := auth.Headers(r)
	if len(userId) == 0 {
		exception.Unauthorized(w)
		return
	}

	query := `
		SELECT row_to_json(row)
		FROM (
			SELECT *
			FROM "User" u
			WHERE u."id" = $1
		) row;
	`
	c.db.WriteJsonString(w, &query, userId)
}

var GetAuthUser = &getAuthUser{db: &db.Instance}
