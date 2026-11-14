package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	if RedactKV("db_password", "hunter2") != Redacted {
		t.Fatal("key redaction")
	}
	for _, in := range []string{"mysql://root:pw@host/db", "api_key=abcdef", "AKIAABCDEFGHIJKLMNOP"} {
		if out := RedactText(in); strings.Contains(out, "pw@") || strings.Contains(out, "abcdef") || strings.Contains(out, "AKIA") {
			t.Fatalf("leak: %s", out)
		}
	}
}

func TestParsers(t *testing.T) {
	l := parseListeners("tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=6))\ntcp LISTEN 0 4 [::1]:9000 [::]:*")
	if len(l) != 2 || l[0].Port != 80 || l[0].Process != "nginx" || l[1].Address != "::1" {
		t.Fatalf("%+v", l)
	}
	s := parseServices("nginx.service loaded active running Nginx\n")
	if len(s) != 1 || s[0].Name != "nginx" {
		t.Fatalf("%+v", s)
	}
}

func TestComposerLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "composer.lock")
	os.WriteFile(p, []byte(`{"packages":[{"name":"a/b","version":"v1.2.3"}],"packages-dev":[]}`), 0o600)
	apps, err := ParseComposerLock(p)
	if err != nil || len(apps) != 1 || apps[0].Version != "1.2.3" {
		t.Fatalf("%v %+v", err, apps)
	}
}
