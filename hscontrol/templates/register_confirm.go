package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// RegisterConfirmInfo carries the information shown on the
// registration confirmation screen.
//
// All fields are pre-filled from IdP claims and device info.
// The user sees them in an editable form and clicks OK or Cancel.
// Whatever is in the fields when OK is clicked gets saved —
// nothing more, nothing less.
//
// ProductMode controls field editability and what gets logged:
//   - Horizon: fields shown for confirmation, saved as-is from IdP.
//     Name/email come from IdP and are displayed but not re-editable
//     (enforced by the IdP group membership gate upstream).
//   - Glue: all fields editable. User may clear any field.
//     Only non-empty confirmed values are stored.
//     No session data (IP, last_seen) is written after registration.
type RegisterConfirmInfo struct {
	// FormAction is the URL the confirm form POSTs to.
	FormAction string

	// CSRFTokenName is the hidden field + cookie name for CSRF.
	CSRFTokenName string

	// CSRFToken is the per-session CSRF token.
	CSRFToken string

	// DisplayName is pre-filled from IdP (name claim).
	// Editable in Glue. Shown-only in Horizon (IdP is authoritative).
	DisplayName string

	// Email is pre-filled from IdP email claim.
	// Horizon: shown, not editable (IdP authoritative).
	// Glue: editable, may be cleared — if cleared, not stored.
	Email string

	// Hostname is pre-filled from the device OS hostname.
	// Both products: editable. User may change to any value.
	// What the user confirms is what gets stored.
	Hostname string

	// OS is the operating system reported by the device.
	// Display only, not editable, not stored as a field.
	OS string

	// MachineKey is the short WireGuard public key fingerprint.
	// Display only — this is the cryptographic identity.
	MachineKey string

	// ProductMode controls field editability and privacy behaviour.
	// "horizon": name/email shown but locked (IdP authoritative).
	// "glue":    all fields editable, email may be cleared.
	ProductMode string
}

// RegisterConfirm renders an interstitial page that asks the
// OIDC-authenticated user to explicitly confirm that they want to
// register the named device under their account. Without this
// confirmation step a single GET to /register/{auth_id} could
// silently complete a phishing-style registration when the victim's
// IdP allows silent SSO.
// fieldStyle is the shared style for editable registration fields.
var fieldStyle = styles.Props{
	styles.Display:      "block",
	styles.Width:        "100%",
	styles.Padding:      "0.4rem 0.6rem",
	styles.MarginTop:    "0.25rem",
	styles.MarginBottom: "1rem",
	styles.Border:       "1px solid var(--md-default-fg-color--lighter)",
	styles.BorderRadius: "4px",
	styles.FontSize:     "0.95rem",
	styles.BoxSizing:    "border-box",
}.ToInline()

// labelStyle is the shared style for field labels.
var labelStyle = styles.Props{
	styles.Display:    "block",
	styles.FontWeight: "600",
	styles.Color:      "var(--md-default-fg-color--light)",
	styles.FontSize:   "0.9rem",
}.ToInline()

// RegisterConfirm renders the editable registration confirmation screen.
//
// All fields are pre-filled and editable. OK saves whatever the user
// confirmed. Cancel aborts with nothing saved.
//
// Horizon: name and email fields are pre-filled from IdP and marked
// readonly — the IdP group gate already validated identity upstream.
// Glue: all fields editable, email has a "leave blank to omit" hint.
func RegisterConfirm(info RegisterConfirmInfo) *elem.Element {
	isGlue := info.ProductMode == "glue"

	nameReadonly := attrs.Props{
		attrs.Type:        "text",
		attrs.Name:        "display_name",
		attrs.Value:       info.DisplayName,
		attrs.Style:       fieldStyle,
		attrs.Placeholder: "Display name",
	}
	if !isGlue {
		nameReadonly[attrs.Readonly] = "true"
	}

	emailReadonly := attrs.Props{
		attrs.Type:        "email",
		attrs.Name:        "email",
		attrs.Value:       info.Email,
		attrs.Style:       fieldStyle,
		attrs.Placeholder: "Email address",
	}
	if !isGlue {
		emailReadonly[attrs.Readonly] = "true"
	}

	var emailHint elem.Node
	if isGlue {
		emailHint = elem.P(attrs.Props{
			attrs.Style: styles.Props{
				styles.FontSize: "0.82rem",
				styles.Color:    "var(--md-default-fg-color--light)",
				styles.Margin:   "-0.75rem 0 1rem",
			}.ToInline(),
		}, elem.Text("Optional — leave blank to register anonymously."))
	} else {
		emailHint = elem.Text("")
	}

	privacyNote := elem.P(attrs.Props{
		attrs.Style: styles.Props{
			styles.FontSize:       "0.82rem",
			styles.Color:          "var(--md-default-fg-color--light)",
			styles.BorderTop:      "1px solid var(--md-default-fg-color--lighter)",
			styles.PaddingTop:     "0.75rem",
			styles.MarginTop:      "0.5rem",
		}.ToInline(),
	})
	if isGlue {
		privacyNote = elem.P(attrs.Props{
			attrs.Style: styles.Props{
				styles.FontSize:   "0.82rem",
				styles.Color:      "var(--md-default-fg-color--light)",
				styles.BorderTop:  "1px solid var(--md-default-fg-color--lighter)",
				styles.PaddingTop: "0.75rem",
				styles.MarginTop:  "0.5rem",
			}.ToInline(),
		}, elem.Text(
			"Glue does not log sessions, source IPs, or traffic. "+
				"Only the details you confirm above are stored. "+
				"If you supplied real information, that is all we have.",
		))
	}

	form := elem.Form(
		attrs.Props{
			attrs.Method: "POST",
			attrs.Action: info.FormAction,
		},
		elem.Input(attrs.Props{
			attrs.Type:  "hidden",
			attrs.Name:  info.CSRFTokenName,
			attrs.Value: info.CSRFToken,
		}),
		elem.Label(attrs.Props{attrs.Style: labelStyle}, elem.Text("Display name")),
		elem.Input(nameReadonly),
		elem.Label(attrs.Props{attrs.Style: labelStyle}, elem.Text("Email")),
		elem.Input(emailReadonly),
		emailHint,
		elem.Label(attrs.Props{attrs.Style: labelStyle}, elem.Text("Device hostname")),
		elem.Input(attrs.Props{
			attrs.Type:        "text",
			attrs.Name:        "hostname",
			attrs.Value:       info.Hostname,
			attrs.Style:       fieldStyle,
			attrs.Placeholder: "Device hostname",
		}),
		elem.P(attrs.Props{
			attrs.Style: styles.Props{
				styles.FontSize: "0.82rem",
				styles.Color:    "var(--md-default-fg-color--light)",
				styles.Margin:   "-0.75rem 0 1rem",
			}.ToInline(),
		}, elem.Text("You can change this. Only what you confirm here is saved.")),
		deviceInfoTable(info),
		privacyNote,
		elem.Div(attrs.Props{
			attrs.Style: styles.Props{
				styles.Display:        "flex",
				styles.Gap:            "0.75rem",
				styles.JustifyContent: "flex-end",
				styles.MarginTop:      "1.5rem",
			}.ToInline(),
		},
			elem.A(attrs.Props{
				attrs.Href: "javascript:window.close()",
				attrs.Style: styles.Props{
					styles.Padding:       "0.5rem 1.25rem",
					styles.Border:        "1px solid var(--md-default-fg-color--lighter)",
					styles.BorderRadius:  "4px",
					styles.TextDecoration:"none",
					styles.Color:         "var(--md-default-fg-color)",
				}.ToInline(),
			}, elem.Text("Cancel")),
			elem.Button(
				attrs.Props{
					attrs.Type: "submit",
					attrs.Style: styles.Props{
						styles.Padding:      "0.5rem 1.25rem",
						styles.Background:   "var(--md-primary-fg-color)",
						styles.Color:        "var(--md-primary-bg-color)",
						styles.Border:       "none",
						styles.BorderRadius: "4px",
						styles.FontWeight:   "600",
						styles.Cursor:       "pointer",
					}.ToInline(),
				},
				elem.Text("OK"),
			),
		),
	)

	titleText := "Confirm registration"
	if isGlue {
		titleText = "Confirm registration — Glue"
	}

	return HtmlStructure(
		elem.Title(nil, elem.Text(titleText)),
		mdTypesetBody(
			headscaleLogo(),
			H2(elem.Text("Confirm your details")),
			P(elem.Text(
				"Review and edit the details below before registering this device. "+
					"Click OK to confirm, or Cancel to abort.",
			)),
			form,
			P(elem.Text(
				"If you do not recognise this device, click Cancel. "+
					"The registration request will expire automatically.",
			)),
			pageFooter(),
		),
	)
}

// deviceInfoTable shows the read-only device properties (OS, machine key).
func deviceInfoTable(info RegisterConfirmInfo) *elem.Element {
	return deviceTable(
		[4][2]string{
			{"OS", displayOrUnknown(info.OS)},
			{"Machine key", info.MachineKey},
			{"", ""},
			{"", ""},
		},
	)
}

func deviceTable(rows [4][2]string) *elem.Element {
	tableRows := make([]elem.Node, 0, len(rows))
	for _, row := range rows {
		val := elem.Node(elem.Text(row[1]))
		if row[0] == "Machine key" {
			val = Code(elem.Text(row[1]))
		}

		tableRows = append(tableRows, elem.Tr(nil,
			elem.Td(attrs.Props{
				attrs.Style: styles.Props{
					styles.Padding:      "0.5rem 1rem 0.5rem 0",
					styles.FontWeight:   "600",
					styles.WhiteSpace:   "nowrap",
					styles.Color:        "var(--md-default-fg-color--light)",
					styles.BorderBottom: cssBorderHS,
				}.ToInline(),
			}, elem.Text(row[0])),
			elem.Td(attrs.Props{
				attrs.Style: styles.Props{
					styles.Padding:      "0.5rem 0",
					styles.BorderBottom: cssBorderHS,
				}.ToInline(),
			}, val),
		))
	}

	return elem.Table(attrs.Props{
		attrs.Style: styles.Props{
			styles.Width:          "100%",
			styles.BorderCollapse: "collapse",
			styles.MarginTop:      "1em",
			styles.MarginBottom:   "1.5em",
		}.ToInline(),
	}, tableRows...)
}

func displayOrUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}

	return s
}
