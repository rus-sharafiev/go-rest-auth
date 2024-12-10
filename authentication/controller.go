package authentication

import (
	"net/http"

	"github.com/rus-sharafiev/go-rest-common/db"
)

type controller struct {
	db *db.Postgres
}

func (c controller) Handler(mux *http.ServeMux, prefix *string) {

	path := ""
	if prefix != nil {
		path = *prefix
	}

	mux.HandleFunc("POST "+path+"/signup", c.signUp)
	mux.HandleFunc("POST "+path+"/signup/{$}", c.signUp)

	mux.HandleFunc("POST "+path+"/signup/verify", c.verifySignup)
	mux.HandleFunc("POST "+path+"/signup/verify/{$}", c.verifySignup)

	mux.HandleFunc("POST "+path+"/login", c.logIn)
	mux.HandleFunc("POST "+path+"/login/{$}", c.logIn)

	mux.HandleFunc("GET "+path+"/logout", c.logOut)
	mux.HandleFunc("GET "+path+"/logout/{$}", c.logOut)

	mux.HandleFunc("GET "+path+"/user", c.getAuthUser)
	mux.HandleFunc("GET "+path+"/user/{$}", c.getAuthUser)

	mux.HandleFunc("GET "+path+"/refresh", c.refresh)
	mux.HandleFunc("GET "+path+"/refresh/{$}", c.refresh)

	mux.HandleFunc("POST "+path+"/password/reset", c.resetPassword)
	mux.HandleFunc("POST "+path+"/password/reset/{$}", c.resetPassword)

	mux.HandleFunc("POST "+path+"/password/update", c.updatePassword)
	mux.HandleFunc("POST "+path+"/password/update/{$}", c.updatePassword)
}

var Controller = &controller{db: &db.Instance}
