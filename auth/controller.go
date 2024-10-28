package auth

import (
	"net/http"
)

type controller struct {
}

func (c controller) Register(args ...string) *http.ServeMux {
	authRouter := http.NewServeMux()

	prefix := ""
	if len(args) == 1 && len(args[0]) != 0 {
		prefix = args[0]
	}

	authRouter.Handle(prefix+"/signup", SignUp)
	authRouter.Handle(prefix+"/signup/verify", VerifySignup)
	authRouter.Handle(prefix+"/login", LogIn)
	authRouter.Handle(prefix+"/logout", LogOut)
	authRouter.Handle(prefix+"/user", GetAuthUser)
	authRouter.Handle(prefix+"/refresh", Refresh)
	authRouter.Handle(prefix+"/password/reset", ResetPassword)
	authRouter.Handle(prefix+"/password/update", UpdatePassword)

	return authRouter
}

var Controller = &controller{}
