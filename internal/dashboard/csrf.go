package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	csrfCookieName = "containgo_dashboard_csrf"
	csrfFormField  = "csrf_token"
	csrfTokenBytes = 32
	maxFormBytes   = 64 << 10
)

// CSRFProtector implements a stateless double-submit-cookie CSRF check.
type CSRFProtector struct {
	secureCookie bool
}

// NewCSRFProtector creates the dashboard CSRF protector.
func NewCSRFProtector(secureCookie bool) *CSRFProtector {
	return &CSRFProtector{
		secureCookie: secureCookie,
	}
}

// Token returns the current browser token or issues a new one.
func (p *CSRFProtector) Token(
	writer http.ResponseWriter,
	request *http.Request,
) (string, error) {
	if request == nil {
		return "", errors.New("request must not be nil")
	}

	if cookie, err := request.Cookie(csrfCookieName); err == nil {
		if validCSRFToken(cookie.Value) {
			return cookie.Value, nil
		}
	}

	tokenBytes := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	http.SetCookie(writer, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((8 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   p.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})

	return token, nil
}

// Validate verifies the CSRF cookie and form token for a state-changing action.
func (p *CSRFProtector) Validate(
	writer http.ResponseWriter,
	request *http.Request,
) error {
	if request == nil {
		return errors.New("request must not be nil")
	}

	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxFormBytes,
	)

	if err := request.ParseForm(); err != nil {
		return fmt.Errorf("parse action form: %w", err)
	}

	cookie, err := request.Cookie(csrfCookieName)
	if err != nil || !validCSRFToken(cookie.Value) {
		return errors.New("CSRF cookie is missing or invalid")
	}

	formToken := strings.TrimSpace(request.FormValue(csrfFormField))
	if !validCSRFToken(formToken) {
		return errors.New("CSRF form token is missing or invalid")
	}

	if subtle.ConstantTimeCompare(
		[]byte(cookie.Value),
		[]byte(formToken),
	) != 1 {
		return errors.New("CSRF token mismatch")
	}

	return nil
}

func validCSRFToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(
		strings.TrimSpace(token),
	)

	return err == nil && len(decoded) == csrfTokenBytes
}
