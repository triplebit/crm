package web

import (
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"time"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/money"
	"triplebit.org/portal/internal/safeerr"
	"triplebit.org/portal/internal/web/viewdata"
	"triplebit.org/portal/web/view"
)

//go:embed static/portal.css
var portalCSS []byte

func (s *Server) registerRoutes() {
	s.get("/{$}", s.home)
	s.get("/static/portal.css", s.stylesheet)
	s.get("/healthz", s.healthz)
	s.getLimited("/login", s.login)
	s.getLimited("/auth/callback", s.callback)
	s.getAuthed("/account", s.account)
	s.getAuthed("/enroll", s.enrollForm)
	s.post("/enroll", s.enrollSubmit)
	s.post("/logout", s.logout)
}

// notices maps a query flag to the sentence the home page shows. Only these
// fixed strings ever render: the flag selects a message, it never carries one,
// so nothing an attacker crafts into a shared URL can put words on the page.
var notices = map[string]string{
	"signed-out":   "You have been signed out.",
	"login-failed": "Sign-in could not be completed. Please try again.",
}

func (c *reqctx) redirectWithNotice(flag string) error {
	http.Redirect(c.w, c.r, "/?notice="+flag, http.StatusSeeOther)
	return nil
}

func (s *Server) home(c *reqctx) error {
	if c.principal != nil && c.r.URL.Query().Get("notice") == "" {
		http.Redirect(c.w, c.r, "/account", http.StatusSeeOther)
		return nil
	}
	layout, err := c.layout("Welcome")
	if err != nil {
		return err
	}
	return view.Home(viewdata.Home{
		Layout: layout,
		Notice: notices[c.r.URL.Query().Get("notice")],
	}).Render(c.r.Context(), c.w)
}

// login starts a Pocket ID sign-in: create the server-side transaction, hand
// the browser the opaque login token, and send it to the authorization URL.
func (s *Server) login(c *reqctx) error {
	if c.principal != nil {
		http.Redirect(c.w, c.r, "/account", http.StatusSeeOther)
		return nil
	}
	authURL, loginToken, err := s.oidc.Begin(c.r.Context())
	if err != nil {
		return err
	}
	s.jar.Set(c.w, s.loginCookie, loginToken.String(), time.Now().Add(s.loginTTL))
	http.Redirect(c.w, c.r, authURL, http.StatusSeeOther)
	return nil
}

// callback finishes the sign-in. The order is deliberate: complete the OIDC
// exchange first, then revoke whatever session the browser presented, then
// issue the new one — a login always rotates the credential, and the old
// session dies before the new cookie exists.
func (s *Server) callback(c *reqctx) error {
	rawLogin, ok := s.jar.Read(c.r, s.loginCookie)
	if !ok {
		return c.redirectWithNotice("login-failed")
	}
	s.jar.Clear(c.w, s.loginCookie)

	query := c.r.URL.Query()
	identity, err := s.oidc.Complete(c.r.Context(), rawLogin, query.Get("state"), query.Get("code"))
	if err != nil {
		if errors.Is(err, auth.ErrLoginFailed) {
			return c.redirectWithNotice("login-failed")
		}
		return err
	}

	if c.rawSession != "" {
		if err := s.sessions.Revoke(c.r.Context(), c.rawSession, "rotated by new sign-in"); err != nil {
			return err
		}
	}
	_, sessionToken, err := s.sessions.SignIn(c.r.Context(), identity)
	if err != nil {
		return err
	}
	// A zero expiry makes this a browser-session cookie: it dies when the
	// browser closes, and the server-side idle and absolute deadlines bound
	// it regardless. The cookie never outlives the session it names.
	s.jar.Set(c.w, s.sessionCookie, sessionToken.String(), time.Time{})
	http.Redirect(c.w, c.r, "/account", http.StatusSeeOther)
	return nil
}

func (s *Server) logout(c *reqctx) error {
	if err := s.sessions.Revoke(c.r.Context(), c.rawSession, "signed out"); err != nil {
		return err
	}
	s.jar.Clear(c.w, s.sessionCookie)
	return c.redirectWithNotice("signed-out")
}

// loginMethodPhrases renders the schema's three login methods as sentences.
var loginMethodPhrases = map[string]string{
	"passkey": "a passkey",
	"email":   "an email link",
	"unknown": "Pocket ID",
}

func (s *Server) account(c *reqctx) error {
	layout, err := c.layout("Your account")
	if err != nil {
		return err
	}
	name := c.principal.User.DisplayName
	if name == "" {
		name = c.principal.User.Email
	}
	phrase := loginMethodPhrases[c.principal.LoginMethod]
	if phrase == "" {
		phrase = loginMethodPhrases["unknown"]
	}
	return view.Account(viewdata.Account{
		Layout:      layout,
		DisplayName: name,
		Email:       c.principal.User.Email,
		LoginMethod: phrase,
		Roles:       c.principal.Roles,
	}).Render(c.r.Context(), c.w)
}

func (s *Server) stylesheet(c *reqctx) error {
	c.w.Header().Set("Content-Type", "text/css; charset=utf-8")
	c.w.Header().Set("Cache-Control", "public, max-age=3600")
	_, err := c.w.Write(portalCSS)
	return err
}

// healthz answers process liveness for the container orchestrator. The handler
// itself touches nothing: a database check belongs to readiness, and the
// migration Verify at startup already covers schema state. Like every route it
// passes through the registrar, so a probe that carried a session cookie would
// load the session first — but orchestrator probes carry no cookies, and
// keeping the route inside the registrar is worth more than optimising a
// request nothing sends.
func (s *Server) healthz(c *reqctx) error {
	c.w.Header().Set("Cache-Control", "no-store")
	_, err := c.w.Write([]byte("ok\n"))
	return err
}

// priceLabel renders "$75.00 / month", "$150.00 / 3 months", "$100.00 one time".
func priceLabel(amount int64, recurringInterval string, intervalCount int64) string {
	label := money.Cents(amount).Display()
	switch {
	case recurringInterval == "":
		return label + " one time"
	case intervalCount <= 1:
		return label + " / " + recurringInterval
	default:
		return fmt.Sprintf("%s / %d %ss", label, intervalCount, recurringInterval)
	}
}

func (s *Server) enrollData(c *reqctx) (viewdata.Enroll, error) {
	layout, err := c.layout("Enroll")
	if err != nil {
		return viewdata.Enroll{}, err
	}
	offer, err := s.checkout.Offer(c.r.Context())
	if err != nil {
		return viewdata.Enroll{}, err
	}
	data := viewdata.Enroll{Layout: layout}
	for _, tier := range offer.Tiers {
		data.Tiers = append(data.Tiers, viewdata.EnrollTier{
			Slug:       tier.Slug,
			Name:       tier.Name,
			PriceLabel: priceLabel(tier.Amount, tier.Interval, tier.IntervalCount),
		})
	}
	if offer.DeviceAvailable {
		data.DeviceAvailable = true
		data.DevicePriceLabel = priceLabel(offer.DeviceAmount, "", 0)
	}
	return data, nil
}

func (s *Server) enrollForm(c *reqctx) error {
	data, err := s.enrollData(c)
	if err != nil {
		return err
	}
	return view.Enroll(data).Render(c.r.Context(), c.w)
}

func (s *Server) enrollSubmit(c *reqctx) error {
	req := checkout.EnrollmentRequest{
		TierSlug:      c.r.PostForm.Get("tier"),
		IncludeDevice: c.r.PostForm.Get("device") == "yes",
		IMEI:          c.r.PostForm.Get("imei"),
	}
	url, err := s.checkout.StartEnrollment(c.r.Context(), checkout.Person{
		UserID: c.principal.User.ID,
		Email:  c.principal.User.Email,
		Name:   c.principal.User.DisplayName,
	}, req)
	if err != nil {
		// A member-safe rejection re-renders the form with their input and
		// the sentence; everything else is the router's problem.
		if !safeerr.IsSafe(err) {
			return err
		}
		data, dataErr := s.enrollData(c)
		if dataErr != nil {
			return dataErr
		}
		data.Error = safeerr.Message(err, "That did not work. Please check the form.")
		data.TierSlug = req.TierSlug
		data.IncludeDevice = req.IncludeDevice
		data.IMEI = req.IMEI
		c.w.WriteHeader(safeerr.StatusOf(err, http.StatusUnprocessableEntity))
		return view.Enroll(data).Render(c.r.Context(), c.w)
	}
	// Off to Stripe's hosted page. 303, so a refresh cannot resubmit.
	http.Redirect(c.w, c.r, url, http.StatusSeeOther)
	return nil
}
