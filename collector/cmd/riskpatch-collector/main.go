// riskpatch-collector: one-shot, read-only fact collector. Collects, uploads once, exits.
// Token is read from RISKPATCH_TOKEN or stdin (--token-stdin); never from argv.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"riskpatch/collector/internal/collect"
)

var (
	version = "0.1.0"
	commit  = "unknown"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if strings.HasPrefix(k, "RISKPATCH_") {
		if v := os.Getenv("STACKWATCH_" + strings.TrimPrefix(k, "RISKPATCH_")); v != "" {
			return v
		}
	}
	return d
}

func die(code int, format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "riskpatch-collector: "+format+"\n", a...)
	os.Exit(code)
}

func main() {
	var (
		urlFlag    = flag.String("url", env("RISKPATCH_URL", ""), "base URL, e.g. https://riskpatch.example.com")
		asset      = flag.String("asset-id", env("RISKPATCH_ASSET_ID", ""), "asset id assigned by Ansible")
		caFile     = flag.String("ca-file", env("RISKPATCH_CA_FILE", ""), "extra CA bundle (PEM); system roots are used otherwise")
		tokenStdin = flag.Bool("token-stdin", false, "read API token from stdin")
		manifests  = flag.String("manifests", env("RISKPATCH_MANIFESTS", ""), "comma-separated composer.lock paths")
		dryRun     = flag.Bool("dry-run", false, "print payload to stdout, do not upload")
		selfDelete = flag.Bool("self-delete", false, "remove this binary after a successful run")
		retries    = flag.Int("retries", 4, "upload attempts")
		showVer    = flag.Bool("version", false, "print version")
	)
	flag.Parse()
	if *showVer {
		fmt.Printf("%s (%s)\n", version, commit)
		return
	}
	if *asset == "" {
		die(2, "asset-id required")
	}
	token := env("RISKPATCH_TOKEN", "")
	if *tokenStdin {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		token = strings.TrimSpace(string(b))
	}
	os.Unsetenv("RISKPATCH_TOKEN")
	os.Unsetenv("STACKWATCH_TOKEN")
	if !*dryRun && (*urlFlag == "" || token == "") {
		die(2, "url and token required")
	}
	if !*dryRun && !strings.HasPrefix(*urlFlag, "https://") && env("RISKPATCH_ALLOW_HTTP", "") != "1" {
		die(2, "url must be https")
	}

	cfg := collect.Config{AssetID: *asset, Version: version, Exposure: collect.Exposure{
		Exposure: env("RISKPATCH_EXPOSURE", "unknown"), Environment: env("RISKPATCH_ENVIRONMENT", "unknown"),
		AuthBoundary: env("RISKPATCH_AUTH_BOUNDARY", "unknown"), Mitigations: splitList(os.Getenv("RISKPATCH_MITIGATIONS")),
	}, Manifests: splitList(*manifests)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	snap := collect.Collect(ctx, cfg)
	body, err := json.Marshal(snap)
	if err != nil {
		die(1, "encode: %v", err)
	}
	if *dryRun {
		os.Stdout.Write(body)
		fmt.Println()
		return
	}
	id, err := upload(ctx, *urlFlag, token, *caFile, body, *retries)
	if err != nil {
		die(1, "upload not confirmed: %v", err)
	}
	fmt.Printf("accepted snapshot_id=%d asset_id=%s\n", id, *asset)
	if *selfDelete {
		if exe, err := os.Executable(); err == nil {
			os.Remove(exe)
		}
	}
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func client(caFile string) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		tc.RootCAs = pool
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// upload retries with exponential backoff on network/5xx/429; 4xx is final. Same payload => server dedupes.
func upload(ctx context.Context, base, token, caFile string, body []byte, attempts int) (int64, error) {
	c, err := client(caFile)
	if err != nil {
		return 0, err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(body)
	zw.Close()
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := time.Duration(1<<uint(i))*time.Second + time.Duration(rand.Intn(500))*time.Millisecond
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(base, "/")+"/api/v1/ingest/snapshots", bytes.NewReader(gz.Bytes()))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := c.Do(req)
		if err != nil {
			last = err
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			var r struct {
				SnapshotID int64  `json:"snapshot_id"`
				Status     string `json:"status"`
			}
			if json.Unmarshal(raw, &r) != nil || r.Status != "accepted" || r.SnapshotID <= 0 {
				return 0, fmt.Errorf("unexpected response body")
			}
			return r.SnapshotID, nil
		}
		last = fmt.Errorf("HTTP %d: %s", resp.StatusCode, collect.RedactText(string(raw[:min(len(raw), 300)])))
		if resp.StatusCode < 500 && resp.StatusCode != 429 {
			return 0, last
		}
	}
	return 0, last
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
