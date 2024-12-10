package auth

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	common "github.com/rus-sharafiev/go-rest-common"
	"github.com/rus-sharafiev/go-rest-common/db"
	"github.com/rus-sharafiev/go-rest-common/exception"
	"github.com/rus-sharafiev/go-rest-common/jwt"
	"github.com/rus-sharafiev/go-rest-common/localization"
	"golang.org/x/crypto/pbkdf2"
)

type logIn struct {
	db *db.Postgres
}

func (c logIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		exception.MethodNotAllowed(w)
		return
	}
	var logInDto LogInDto
	json.NewDecoder(r.Body).Decode(&logInDto)

	var userPswd UserPswd
	pswdQuery := `
		SELECT u.id, p.password_hash
		FROM users u
		LEFT JOIN passwords p
		ON u.id = p.user_id
		WHERE u.email = $1;
	`
	if err := c.db.QueryRow(&pswdQuery, logInDto.Email).Scan(&userPswd.UserId, &userPswd.PasswordHash); err != nil {
		if err == pgx.ErrNoRows {
			exception.BadRequestFields(w, map[string]string{
				"email": localization.SelectString(r, localization.Langs{
					En: "Email does not exist",
					Ru: "Email не зарегистрирован",
				}),
			})
		} else {
			exception.InternalServerError(w, err)
		}
		return
	}

	passwordHashAndSalt := strings.Split(userPswd.PasswordHash, ".")
	passwordFromDb := passwordHashAndSalt[0]
	salt, err := base64.StdEncoding.DecodeString(passwordHashAndSalt[1])
	if err != nil {
		exception.InternalServerError(w, err)
		return
	}

	hash := pbkdf2.Key([]byte(logInDto.Password), salt, 4096, 32, sha1.New)
	providedPassword := base64.StdEncoding.EncodeToString(hash)

	if passwordFromDb != providedPassword {
		exception.BadRequestFields(w, map[string]string{
			"password": localization.SelectString(r, localization.Langs{
				En: "Incorrect password",
				Ru: "Неверный пароль",
			}),
		})
		return
	}

	query := `SELECT * FROM users WHERE id = $1;`
	rows, _ := c.db.Query(&query, userPswd.UserId)
	userData, err := pgx.CollectOneRow(rows, pgx.RowToStructByPos[UserData])
	if err != nil {
		exception.InternalServerError(w, err)
		return
	}

	token, err := jwt.GenerateAccessToken(*userData.ID, *userData.Access)
	if err != nil {
		exception.InternalServerError(w, err)
		return
	}

	result := LoginResult{
		User:        userData,
		AccessToken: token,
	}

	refreshToken, err := jwt.GenerateRefreshToken(*userData.ID, *userData.Access)
	if err != nil {
		exception.InternalServerError(w, err)
		return
	}

	if common.Config.RefreshCookiePath != nil {

		// Set cookie with refresh token
		cookie := &http.Cookie{
			Name:   "refresh-token",
			Value:  "Bearer " + refreshToken,
			Path:   *common.Config.RefreshCookiePath,
			MaxAge: 0,
		}
		http.SetCookie(w, cookie)

	} else {

		// Add refresh token to login result
		result.RefreshToken = &refreshToken
	}

	if fingerprint := r.Header.Get("Fingerprint"); len(fingerprint) != 0 {

		query := `
			INSERT INTO sessions (user_id, fingerprint, user_agent, ip, updated_at) 
			VALUES (@userId, @fingerprint, @userAgent, @ip, CURRENT_TIMESTAMP)
			ON CONFLICT (fingerprint) DO 
				UPDATE SET (user_id, user_agent, ip, updated_at) = 
				(EXCLUDED.user_id, EXCLUDED.user_agent, EXCLUDED.ip, EXCLUDED.updated_at);
		`
		args := pgx.NamedArgs{
			"userId":      userData.ID,
			"fingerprint": fingerprint,
			"userAgent":   r.Header.Get("User-Agent"),
			"ip":          strings.Split(r.RemoteAddr, ":")[0],
		}

		if _, err := c.db.Query(&query, args); err != nil {
			exception.InternalServerError(w, err)
			return
		}
	}

	// OK response
	json.NewEncoder(w).Encode(&result)
}

var LogIn = &logIn{db: &db.Instance}
