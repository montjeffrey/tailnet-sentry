package quarantine

import (
	"strings"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

func device(tags ...string) inventory.Device {
	return inventory.Device{ID: "nKALI", Name: "kali.example.ts.net", Owner: "mallory@example.com", Tags: tags, Authorized: true}
}

func steps(p Plan) string {
	var s []string
	for _, st := range p.Steps {
		switch st.Kind {
		case SetTags:
			s = append(s, "tags="+strings.Join(st.Tags, ","))
		case SetAuthorized:
			if st.Authorized {
				s = append(s, "authorize")
			} else {
				s = append(s, "deauthorize")
			}
		}
	}
	return strings.Join(s, " ")
}

func TestPlanIsolate(t *testing.T) {
	tests := []struct {
		name        string
		dev         inventory.Device
		deauthorize bool
		wantSteps   string
		wantNote    string
	}{
		{"user-owned", device(), false, "tags=tag:quarantine", "release cannot give it back"},
		{"tagged replaces all tags", device("tag:server", "tag:prod"), false, "tags=tag:quarantine", "restore [tag:server, tag:prod]"},
		{"deauthorize comes first", device("tag:ci"), true, "deauthorize tags=tag:quarantine", PolicyNote},
		{"deauthorize an already-tagged device", device("tag:quarantine"), true, "deauthorize", PolicyNote},
		{"already quarantined", device("tag:quarantine"), false, "", "already quarantined"},
		{"quarantined but other tags too", device("tag:quarantine", "tag:server"), false, "tags=tag:quarantine", ""},
		{"already deauthorized", func() inventory.Device { d := device("tag:quarantine"); d.Authorized = false; return d }(), true, "", "already deauthorized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := PlanIsolate(tt.dev, tt.deauthorize)
			if err != nil {
				t.Fatal(err)
			}
			if got := steps(p); got != tt.wantSteps {
				t.Errorf("steps = %q, want %q", got, tt.wantSteps)
			}
			if tt.wantNote != "" && !strings.Contains(strings.Join(p.Notes, "\n"), tt.wantNote) {
				t.Errorf("notes %q lack %q", p.Notes, tt.wantNote)
			}
		})
	}
}

func TestPlanIsolateAlwaysWarnsAboutPolicy(t *testing.T) {
	p, _ := PlanIsolate(device(), false)
	if !strings.Contains(strings.Join(p.Notes, "\n"), "blocks nothing until your tailnet policy") {
		t.Error("isolate must say that tagging alone does nothing")
	}
}

func TestPlanIsolateWarnsAboutRoutes(t *testing.T) {
	router := device("tag:router")
	router.EnabledRoutes = []string{"192.168.1.0/24"}
	p, _ := PlanIsolate(router, false)
	if !strings.Contains(strings.Join(p.Notes, " "), "tags do not revoke approved routes") {
		t.Errorf("router isolate must warn about routes: %q", p.Notes)
	}
	p, _ = PlanIsolate(router, true)
	if strings.Contains(strings.Join(p.Notes, " "), "tags do not revoke") {
		t.Error("deauthorizing already cuts the router off; no warning needed")
	}
}

func TestPlanIsolateRefusesExternal(t *testing.T) {
	d := device()
	d.External = true
	if _, err := PlanIsolate(d, false); err == nil {
		t.Error("shared-in devices cannot be tagged; want error")
	}
}

func TestPlanRelease(t *testing.T) {
	deauthed := device("tag:quarantine")
	deauthed.Authorized = false
	tests := []struct {
		name        string
		dev         inventory.Device
		restore     []string
		reauthorize bool
		wantSteps   string
		wantNote    string
		wantErr     bool
	}{
		{"restore tags", device("tag:quarantine"), []string{"tag:server"}, false, "tags=tag:server", "", false},
		{"restore ignores quarantine tag", device("tag:quarantine"), []string{"tag:quarantine", "tag:ci"}, false, "tags=tag:ci", "", false},
		{"was user-owned", device("tag:quarantine"), nil, false, "", "--force-reauth", false},
		{"also reauthorize", deauthed, []string{"tag:server"}, true, "tags=tag:server authorize", "", false},
		{"never approve a device sentry did not deauthorize", deauthed, []string{"tag:server"}, false, "tags=tag:server", "stays unauthorized", false},
		{"not quarantined", device("tag:server"), nil, false, "", "", true},
		{"only deauthorized", func() inventory.Device { d := device("tag:server"); d.Authorized = false; return d }(), nil, true, "authorize", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := PlanRelease(tt.dev, tt.restore, tt.reauthorize)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if err != nil {
				return
			}
			if got := steps(p); got != tt.wantSteps {
				t.Errorf("steps = %q, want %q", got, tt.wantSteps)
			}
			if tt.wantNote != "" && !strings.Contains(strings.Join(p.Notes, "\n"), tt.wantNote) {
				t.Errorf("notes %q lack %q", p.Notes, tt.wantNote)
			}
		})
	}
}

func TestGuardSelf(t *testing.T) {
	d := device()
	tests := []struct {
		name                        string
		isSelf, known, apply, force bool
		wantErr                     bool
	}{
		{"other device", false, true, true, false, false},
		{"self", true, true, false, false, true},
		{"self apply", true, true, true, false, true},
		{"self forced", true, true, true, true, false},
		{"unknown self, dry run", false, false, false, false, false},
		{"unknown self, apply", false, false, true, false, true},
		{"unknown self, forced", false, false, true, true, false},
	}
	for _, tt := range tests {
		if err := GuardSelf(d, tt.isSelf, tt.known, tt.apply, tt.force); (err != nil) != tt.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestParseTags(t *testing.T) {
	got, err := ParseTags(" tag:server, tag:prod ,")
	if err != nil || strings.Join(got, ",") != "tag:server,tag:prod" {
		t.Errorf("ParseTags = %v, %v", got, err)
	}
	for _, bad := range []string{"server", "tag:", "tag:a b"} {
		if _, err := ParseTags(bad); err == nil {
			t.Errorf("ParseTags(%q) should fail", bad)
		}
	}
}
