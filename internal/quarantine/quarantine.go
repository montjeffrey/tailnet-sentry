// Package quarantine plans isolate and release. Planning is pure: it takes a
// device and returns the exact API calls that would be made, so the dry run
// prints precisely what --apply will do, and both are tested the same way.
//
// How isolation works, and its limits:
//
//   - Isolate REPLACES the device's tags with only tag:quarantine. Adding the
//     tag alongside the old ones would leave every grant for those old tags
//     in force; for a user-owned device, tagging also detaches it from the
//     user, so grants to that user stop applying too.
//   - None of that blocks traffic by itself. The tailnet policy decides what
//     tag:quarantine may reach; examples/quarantine-policy.hujson is a policy
//     in which it reaches nothing. Until that policy is applied, isolate
//     only relabels the device.
//   - --deauthorize additionally revokes the device's authorization, which
//     disconnects it entirely where device approval is enabled. It runs
//     before the tags change, so a failure part-way never leaves a device
//     relabelled but still connected.
//   - Tags do not touch a device's approved subnet routes or exit node.
//     Routed traffic is allowed by grants to the routed CIDR (or
//     autogroup:internet), not by the router's own tags, so a quarantined
//     router can keep forwarding. The plan says so; --deauthorize, or
//     revoking the routes in the admin console, is the fix.
//   - Tailscale does not let a device lose every tag through the API. A
//     device that was user-owned before isolation therefore cannot be handed
//     back by release; it has to re-authenticate as its user.
package quarantine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/rules"
)

// Tag is the quarantine tag.
const Tag = rules.QuarantineTag

// Kinds of step.
const (
	SetTags       = "set-tags"
	SetAuthorized = "set-authorized"
)

// Step is one API call.
type Step struct {
	Kind       string
	Tags       []string // for SetTags
	Authorized bool     // for SetAuthorized
}

func (s Step) String() string {
	switch s.Kind {
	case SetTags:
		return "set tags to " + list(s.Tags) + "  (POST /api/v2/device/{id}/tags)"
	case SetAuthorized:
		if s.Authorized {
			return "re-authorize the device  (POST /api/v2/device/{id}/authorized)"
		}
		return "deauthorize the device  (POST /api/v2/device/{id}/authorized)"
	}
	return s.Kind
}

// Plan is what isolate or release would do to one device.
type Plan struct {
	Action       string // "isolate" or "release"
	Device       inventory.Device
	Steps        []Step
	PreviousTags []string
	NewTags      []string
	Deauthorize  bool
	Reauthorize  bool
	Notes        []string
}

// PolicyNote is shown with every isolate, because it is the step people miss.
const PolicyNote = "tag:quarantine blocks nothing until your tailnet policy denies it; " +
	"apply examples/quarantine-policy.hujson (or its rules) first"

// PlanIsolate plans quarantining d.
//
// Deauthorizing, when asked for, comes first. It is the step that actually
// disconnects the device, including any subnet routes or exit node it
// serves, which tags do not touch. If a later step then fails, the device is
// left disconnected but not yet tagged, which is the safer partial state; the
// other order could leave it tagged, still authorized and still forwarding.
func PlanIsolate(d inventory.Device, deauthorize bool) (Plan, error) {
	if d.External {
		return Plan{}, fmt.Errorf("%s is shared in from outside this tailnet and cannot be tagged here; remove the share in the admin console instead", d.ShortName())
	}
	p := Plan{Action: "isolate", Device: d, PreviousTags: copyTags(d.Tags), NewTags: []string{Tag}}
	if deauthorize {
		if d.Authorized {
			p.Steps = append(p.Steps, Step{Kind: SetAuthorized, Authorized: false})
			p.Deauthorize = true
		} else {
			p.Notes = append(p.Notes, "device is already deauthorized")
		}
	}
	if !(len(d.Tags) == 1 && d.Tags[0] == Tag) {
		p.Steps = append(p.Steps, Step{Kind: SetTags, Tags: []string{Tag}})
	}
	if len(p.Steps) == 0 {
		p.Notes = append(p.Notes, "device is already quarantined; nothing to do")
		return p, nil
	}
	p.Notes = append(p.Notes, PolicyNote)
	if (len(d.EnabledRoutes) > 0 || d.ExitNode()) && !p.Deauthorize {
		p.Notes = append(p.Notes, "this device serves subnet routes or is an exit node; tags do not revoke "+
			"approved routes, so it may keep forwarding traffic. Add --deauthorize, or revoke its routes in the admin console")
	}
	if len(d.Tags) == 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("%s is owned by %s; tagging moves its ownership to tag:quarantine. "+
			"Tailscale cannot remove every tag through the API, so release cannot give it back: "+
			"after release it must re-authenticate as its user (`tailscale up --force-reauth` on the device)",
			d.ShortName(), orUnknown(d.Owner)))
	} else if len(p.PreviousTags) > 0 && !(len(d.Tags) == 1 && d.Tags[0] == Tag) {
		p.Notes = append(p.Notes, "release will restore "+list(p.PreviousTags))
	}
	return p, nil
}

// PlanRelease plans undoing isolate. restoreTags are the tags the device had
// before isolation (from the audit log, the baseline or --restore-tags);
// empty means it was user-owned. reauthorize is true only when sentry itself
// deauthorized the device (per the audit log) or the operator asked: a
// device that was awaiting approval before isolation must not come out of
// quarantine approved.
func PlanRelease(d inventory.Device, restoreTags []string, reauthorize bool) (Plan, error) {
	quarantined := d.HasTag(Tag)
	if !quarantined && d.Authorized {
		return Plan{}, fmt.Errorf("%s is not quarantined (tags %s) and is authorized; nothing to release", d.ShortName(), list(d.Tags))
	}
	restore := withoutQuarantine(restoreTags)
	p := Plan{Action: "release", Device: d, PreviousTags: copyTags(d.Tags), NewTags: copyTags(d.Tags)}
	if quarantined {
		if len(restore) > 0 {
			p.Steps = append(p.Steps, Step{Kind: SetTags, Tags: restore})
			p.NewTags = restore
		} else {
			p.Notes = append(p.Notes, fmt.Sprintf("%s had no tags before isolation (it was user-owned). "+
				"Tailscale cannot remove every tag through the API, so it stays tagged tag:quarantine until it "+
				"re-authenticates as its user: run `tailscale up --force-reauth` on that device. "+
				"If it had tags, pass them with --restore-tags", d.ShortName()))
		}
	}
	if !d.Authorized {
		if reauthorize {
			p.Steps = append(p.Steps, Step{Kind: SetAuthorized, Authorized: true})
			p.Reauthorize = true
		} else {
			p.Notes = append(p.Notes, "device is not authorized and sentry has no record of deauthorizing it; "+
				"it stays unauthorized (pass --reauthorize to approve it)")
		}
	}
	if len(p.Steps) == 0 && len(p.Notes) == 0 {
		return Plan{}, errors.New("nothing to release")
	}
	return p, nil
}

// GuardSelf refuses to isolate the device sentry runs on, which would cut
// the operator off from the machine they are using to respond. When sentry
// cannot tell which device it is on, an --apply is refused too: failing
// closed is the safe default for a command that disconnects machines.
func GuardSelf(target inventory.Device, isSelf, selfKnown, apply, force bool) error {
	if force {
		return nil
	}
	if isSelf {
		return fmt.Errorf("%s is the device sentry is running on; isolating it would cut you off. Pass --force if you really mean it", target.ShortName())
	}
	if !selfKnown && apply {
		return errors.New("cannot tell which device sentry is running on (is tailscaled running here?); refusing to apply without --force")
	}
	return nil
}

// ParseTags splits a comma-separated --restore-tags value and checks each
// entry looks like a tag.
func ParseTags(s string) ([]string, error) {
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "tag:") || len(t) == len("tag:") || strings.ContainsAny(t, " \t") {
			return nil, fmt.Errorf("%q is not a tag like tag:server", t)
		}
		out = append(out, t)
	}
	return out, nil
}

func withoutQuarantine(tags []string) []string {
	var out []string
	for _, t := range tags {
		if t != Tag {
			out = append(out, t)
		}
	}
	return out
}

func copyTags(t []string) []string {
	if len(t) == 0 {
		return []string{}
	}
	return append([]string(nil), t...)
}

func list(tags []string) string {
	if len(tags) == 0 {
		return "[]"
	}
	return "[" + strings.Join(tags, ", ") + "]"
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown user"
	}
	return s
}
