// Package viewdata holds the plain structs templates render.
//
// Everything here is a pre-formatted string or a bool. Handlers do all
// formatting — dates, money, pluralisation — before a template sees the data,
// so templates contain no logic worth testing and layercheck R4 can confine
// web/view to importing exactly this package. No domain type, no redact.Text,
// no time.Time crosses the boundary: if a value reaches here, it has already
// been made safe and human-readable.
package viewdata

// Layout is what every page shows: the frame around the content.
type Layout struct {
	BrandName    string
	BrandTagline string
	// Title is the page-specific part of the <title>.
	Title string

	// SignedIn switches the header between the sign-in link and the
	// sign-out form; UserName and CSRFToken are only set when it is true.
	SignedIn  bool
	UserName  string
	CSRFToken string
}

// Home is the landing page.
type Home struct {
	Layout

	// Notice is a human-readable line shown above the sign-in button, used
	// for "sign-in failed" and "signed out". Never an error's text.
	Notice string
}

// Account is the member's own page: the M3 gate is rendering this with the
// member's name after a Pocket ID sign-in.
type Account struct {
	Layout

	DisplayName string
	Email       string
	// LoginMethod is the human phrasing, e.g. "a passkey".
	LoginMethod string
	Roles       []string
}
