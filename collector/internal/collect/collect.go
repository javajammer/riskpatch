package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SchemaVersion    = "1.0"
	maxOutput        = 4 << 20
	cmdTimeout       = 15 * time.Second
	maxPackages      = 30000
	maxManifestBytes = 16 << 20
)

type Config struct {
	AssetID          string
	Version          string
	Exposure         Exposure
	Manifests        []string // explicit composer.lock paths
	PhpIniDirectives []string
}

type Exposure struct {
	Exposure     string            `json:"exposure"`
	Environment  string            `json:"environment"`
	AuthBoundary string            `json:"auth_boundary"`
	Mitigations  []string          `json:"mitigations"`
	Labels       map[string]string `json:"labels,omitempty"`
}

type Snapshot struct {
	SchemaVersion    string   `json:"schema_version"`
	AssetID          string   `json:"asset_id"`
	CollectedAt      string   `json:"collected_at"`
	CollectorVersion string   `json:"collector_version"`
	Facts            Facts    `json:"facts"`
	Errors           []string `json:"errors"`
}

type Facts struct {
	OS        OS            `json:"os"`
	Hostname  string        `json:"hostname"`
	Runtimes  []Runtime     `json:"runtimes"`
	Packages  []Package     `json:"packages"`
	Services  []Service     `json:"services"`
	Listening []Listener    `json:"listening_ports"`
	Modules   []string      `json:"modules"`
	Config    []ConfigFact  `json:"config_facts"`
	Apps      []Application `json:"applications"`
	Exposure  Exposure      `json:"exposure"`
}

type OS struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	ID      string `json:"id"`
	IDLike  string `json:"id_like"`
	Kernel  string `json:"kernel"`
	Arch    string `json:"arch"`
}
type Runtime struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Sapi    string `json:"sapi,omitempty"`
	Path    string `json:"path,omitempty"`
}
type Package struct {
	Name, Version, Arch, Manager string
}

func (p Package) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"name": p.Name, "version": p.Version, "arch": p.Arch, "manager": p.Manager})
}

type Service struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type Listener struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
}
type ConfigFact struct {
	Source string `json:"source"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}
type Application struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Direct    *bool  `json:"direct,omitempty"`
	Manifest  string `json:"manifest,omitempty"`
}

// run executes one allowlisted command with a timeout and an output cap. Never through a shell.
func run(ctx context.Context, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	var out, errb limited
	out.max, errb.max = maxOutput, 64<<10
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	err = cmd.Run()
	// some tools (java -version, nginx -v) print to stderr
	text := out.buf.String()
	if strings.TrimSpace(text) == "" {
		text = errb.buf.String()
	}
	return text, err
}

type limited struct {
	buf bytes.Buffer
	max int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil // swallow overflow so the child is not blocked
}

func readSmall(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b := make([]byte, limit)
	n, _ := f.Read(b)
	return string(b[:n]), nil
}

var verRe = regexp.MustCompile(`\d+(?:\.\d+)+[A-Za-z0-9._+~-]*`)

func firstVersion(s string) string { return verRe.FindString(s) }

// Collect gathers every fact; individual failures are recorded in Errors and never abort the run.
func Collect(ctx context.Context, cfg Config) Snapshot {
	snap := Snapshot{SchemaVersion: SchemaVersion, AssetID: cfg.AssetID, CollectorVersion: cfg.Version,
		CollectedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Errors: []string{}}
	f := &snap.Facts
	f.Exposure = cfg.Exposure
	f.Hostname, _ = os.Hostname()
	fail := func(what string, err error) {
		if err != nil && len(snap.Errors) < 200 {
			snap.Errors = append(snap.Errors, RedactText(what+": "+err.Error()))
		}
	}
	fail("os", collectOS(ctx, &f.OS))
	fail("packages", collectPackages(ctx, f))
	collectRuntimes(ctx, f, fail)
	if out, err := run(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"); err == nil {
		f.Services = parseServices(out)
	} else {
		fail("services", err)
	}
	if out, err := run(ctx, "ss", "-H", "-ltnup"); err == nil {
		f.Listening = parseListeners(out)
	} else {
		fail("listening_ports", err)
	}
	collectPhpConfig(ctx, f, cfg, fail)
	for _, m := range cfg.Manifests {
		apps, err := ParseComposerLock(m)
		fail("manifest "+m, err)
		f.Apps = append(f.Apps, apps...)
	}
	return normalize(snap)
}

func normalize(s Snapshot) Snapshot {
	f := &s.Facts
	if f.Runtimes == nil {
		f.Runtimes = []Runtime{}
	}
	if f.Packages == nil {
		f.Packages = []Package{}
	}
	if f.Services == nil {
		f.Services = []Service{}
	}
	if f.Listening == nil {
		f.Listening = []Listener{}
	}
	if f.Modules == nil {
		f.Modules = []string{}
	}
	if f.Config == nil {
		f.Config = []ConfigFact{}
	}
	if f.Apps == nil {
		f.Apps = []Application{}
	}
	if f.Exposure.Mitigations == nil {
		f.Exposure.Mitigations = []string{}
	}
	return s
}

func collectOS(ctx context.Context, o *OS) error {
	text, err := readSmall("/etc/os-release", 8192)
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "NAME":
			o.Name = strings.TrimSuffix(strings.TrimSuffix(v, " Linux"), " GNU/Linux")
		case "VERSION_ID":
			o.Version = v
		case "ID":
			o.ID = strings.Trim(v, "\"")
		case "ID_LIKE":
			o.IDLike = v
		}
	}
	if k, e := run(ctx, "uname", "-r"); e == nil {
		o.Kernel = strings.TrimSpace(k)
	}
	if a, e := run(ctx, "uname", "-m"); e == nil {
		o.Arch = strings.TrimSpace(a)
	}
	return err
}

func collectPackages(ctx context.Context, f *Facts) error {
	if out, err := run(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			p := strings.Split(line, "\t")
			if len(p) == 4 && strings.HasPrefix(strings.TrimSpace(p[3]), "ii") && len(f.Packages) < maxPackages {
				f.Packages = append(f.Packages, Package{p[0], p[1], p[2], "dpkg"})
			}
		}
		return nil
	}
	out, err := run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	if err != nil {
		return fmt.Errorf("no dpkg or rpm: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		p := strings.Split(line, "\t")
		if len(p) == 3 && len(f.Packages) < maxPackages {
			f.Packages = append(f.Packages, Package{p[0], strings.TrimPrefix(p[1], "(none):"), p[2], "rpm"})
		}
	}
	return nil
}

func collectRuntimes(ctx context.Context, f *Facts, fail func(string, error)) {
	type probe struct {
		name, bin string
		args      []string
	}
	for _, p := range []probe{
		{"php", "php", []string{"-v"}}, {"python", "python3", []string{"--version"}},
		{"node", "node", []string{"--version"}}, {"java", "java", []string{"-version"}},
		{"go", "go", []string{"version"}}, {"nginx", "nginx", []string{"-v"}},
		{"apache", "apache2", []string{"-v"}}, {"apache", "httpd", []string{"-v"}},
		{"linux", "uname", []string{"-r"}},
	} {
		out, err := run(ctx, p.bin, p.args...)
		if err != nil && out == "" {
			continue // not installed
		}
		if v := firstVersion(out); v != "" {
			path, _ := exec.LookPath(p.bin)
			f.Runtimes = append(f.Runtimes, Runtime{Name: p.name, Version: v, Path: path})
		}
	}
	if out, err := run(ctx, "php-fpm", "-v"); err == nil {
		if v := firstVersion(out); v != "" {
			f.Runtimes = append(f.Runtimes, Runtime{Name: "php", Version: v, Sapi: "fpm"})
		}
	}
	if out, err := run(ctx, "php", "-m"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "[") && len(f.Modules) < 2000 {
				f.Modules = append(f.Modules, l)
			}
		}
	}
}

func parseServices(out string) []Service {
	var res []Service
	for _, line := range strings.Split(out, "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 4 && strings.HasSuffix(fs[0], ".service") && len(res) < 2000 {
			res = append(res, Service{Name: strings.TrimSuffix(fs[0], ".service"), Status: fs[3]})
		}
	}
	return res
}

var procRe = regexp.MustCompile(`"([^"]+)"`)

func parseListeners(out string) []Listener {
	var res []Listener
	for _, line := range strings.Split(out, "\n") {
		fs := strings.Fields(line)
		if len(fs) < 5 {
			continue
		}
		addr := fs[4]
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(addr[i+1:])
		if err != nil || len(res) >= 2000 {
			continue
		}
		proc := ""
		if m := procRe.FindStringSubmatch(line); m != nil {
			proc = m[1]
		}
		res = append(res, Listener{Proto: fs[0], Address: strings.Trim(addr[:i], "[]"), Port: port, Process: proc})
	}
	return res
}

// Only these php.ini directives are ever read (defaults; cfg.PhpIniDirectives extends them).
var defaultPhpDirectives = []string{"expose_php", "display_errors", "allow_url_fopen", "allow_url_include", "disable_functions", "open_basedir", "memory_limit", "upload_max_filesize", "session.cookie_httponly", "session.cookie_secure"}

func collectPhpConfig(ctx context.Context, f *Facts, cfg Config, fail func(string, error)) {
	if !hasRuntime(f, "php") {
		return
	}
	for _, d := range append(append([]string{}, defaultPhpDirectives...), cfg.PhpIniDirectives...) {
		if out, err := run(ctx, "php", "-r", "echo ini_get('"+sanitizeKey(d)+"');"); err == nil {
			f.Config = append(f.Config, ConfigFact{Source: "php.ini", Key: d, Value: RedactKV(d, strings.TrimSpace(out))})
		}
	}
}

func sanitizeKey(s string) string {
	return regexp.MustCompile(`[^A-Za-z0-9_.]`).ReplaceAllString(s, "")
}

func hasRuntime(f *Facts, name string) bool {
	for _, r := range f.Runtimes {
		if r.Name == name {
			return true
		}
	}
	return false
}

// ParseComposerLock reads an explicitly given composer.lock; paths are never discovered.
func ParseComposerLock(path string) ([]Application, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxManifestBytes {
		return nil, fmt.Errorf("manifest too large")
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if err := json.NewDecoder(bufio.NewReader(bytes.NewReader(raw))).Decode(&lock); err != nil {
		return nil, err
	}
	var apps []Application
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		apps = append(apps, Application{Ecosystem: "Packagist", Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), Manifest: filepath.Base(path)})
	}
	return apps, nil
}
