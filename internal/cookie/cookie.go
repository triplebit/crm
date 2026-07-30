// Package cookie is the only place in the portal that constructs a Set-Cookie
// header.
//
// It exists because of a specific bug. The previous implementation set a cookie
// named "__Host-triplebit_passkey_prompt" with Path=/account. The __Host- prefix
// requires Path=/, so every browser silently discarded it and the feature it
// controlled could never work in production. The session manager guarded against
// exactly that mistake; the general-purpose cookie helper did not, because it
// exposed Path and Domain as caller-supplied fields.
//
// So no exported type here has a Path or Domain field. The path is a literal at
// the single place a cookie is rendered, and the __Host- prefix is derived from
// the transport rather than typed by hand, which means prefix and path cannot
// disagree. `make lint-cookie` fails the build if http.SetCookie or
// &http.Cookie{} appears anywhere outside this package.
package cookie

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"triplebit.org/portal/internal/core"
)

// hostPrefix is required by browsers to imply Secure, Path=/ and no Domain.
// Using it means a cookie set by this host cannot be overwritten by a sibling
// subdomain, which matters because Pocket ID runs on one.
const hostPrefix = "__Host-"

var suffixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Name is a validated, fully-qualified cookie name. It can only be produced by
// Jar.Name, so the prefix decision is made in exactly one place.
//
// The zero value panics on use rather than producing an empty Set-Cookie name.
type Name struct{ v string }

// String returns the wire name.
func (n Name) String() string {
	if n.v == "" {
		panic("cookie: zero Name used; names must come from Jar.Name")
	}
	return n.v
}

// Jar writes every cookie the portal sets.
type Jar struct {
	secure bool
	now    func() time.Time
}

// NewJar derives cookie security from the base URL. Production must be https,
// and is refused otherwise: without Secure, a session cookie travels in clear
// text, and non-https also rules out the __Host- prefix.
func NewJar(base *url.URL, env core.Environment) (*Jar, error) {
	if base == nil {
		return nil, errors.New("cookie: base URL is required")
	}
	secure := base.Scheme == "https"
	if env.IsProduction() && !secure {
		return nil, fmt.Errorf("cookie: production requires an https base URL, got %q", base.Scheme)
	}
	return &Jar{secure: secure, now: time.Now}, nil
}

// Name qualifies a bare suffix such as "session" into a wire name, adding the
// __Host- prefix when the transport supports it. Callers never type the prefix,
// so it cannot be paired with a path that contradicts it.
func (j *Jar) Name(suffix string) Name {
	if !suffixPattern.MatchString(suffix) {
		panic(fmt.Sprintf("cookie: invalid name suffix %q", suffix))
	}
	if j.secure {
		return Name{v: hostPrefix + "tb_" + suffix}
	}
	return Name{v: "tb_" + suffix}
}

// Set writes a cookie that expires at the given time. A zero expiry makes it a
// session cookie, discarded when the browser closes.
func (j *Jar) Set(w http.ResponseWriter, name Name, value string, expires time.Time) {
	c := &http.Cookie{
		Name:  name.String(),
		Value: value,
		// Literal, and the only path this package will ever write. There is no
		// parameter and no struct field through which it could become anything
		// else, which is what makes the __Host- prefix always correct.
		Path: "/",
		// Domain is deliberately absent: __Host- forbids it, and a host-only
		// cookie is what we want regardless.
		HttpOnly: true,
		Secure:   j.secure,
		SameSite: http.SameSiteLaxMode,
	}
	if !expires.IsZero() {
		c.Expires = expires
		if seconds := int(time.Until(expires).Seconds()); seconds > 0 {
			c.MaxAge = seconds
		} else {
			c.MaxAge = -1
		}
	}
	http.SetCookie(w, c)
}

// Clear expires a cookie immediately.
func (j *Jar) Clear(w http.ResponseWriter, name Name) {
	http.SetCookie(w, &http.Cookie{
		Name:     name.String(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   j.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// Read returns the cookie's value, and whether it was present and non-empty.
func (j *Jar) Read(r *http.Request, name Name) (string, bool) {
	c, err := r.Cookie(name.String())
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// Secure reports whether cookies are being written with the Secure attribute,
// which is also whether the __Host- prefix is in use.
func (j *Jar) Secure() bool { return j.secure }
