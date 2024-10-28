package auth

type config struct {
	RefreshCookiePath *string `json:"refreshCookiePath"`
}

var Config config
