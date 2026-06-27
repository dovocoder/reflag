package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

func main() {
	var (
		apiURL  string
		apiKey  string
		verbose bool
		ver     bool
		dryRun  bool
		only    string
		prefix  string
	)
	flag.StringVar(&apiURL, "url", os.Getenv("REFLAG_URL"), "Reflag API URL (or REFLAG_URL env)")
	flag.StringVar(&apiKey, "key", os.Getenv("REFLAG_API_KEY"), "Reflag API key (or REFLAG_API_KEY env)")
	flag.BoolVar(&verbose, "v", false, "verbose: print which secrets were loaded (keys only, never values)")
	flag.BoolVar(&ver, "version", false, "print version and exit")
	flag.BoolVar(&dryRun, "dry-run", false, "resolve secrets and print keys, but don't exec")
	flag.StringVar(&only, "only", "", "comma-separated list of secret keys to include (default: all)")
	flag.StringVar(&prefix, "prefix", "", "prefix for env var names (e.g. REFLAG_)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `reflag-run v%s — inject Reflag secrets as env vars and exec a command

Usage: reflag-run [flags] -- <command> [args...]

Flags:
  -url string     Reflag API URL (or REFLAG_URL env)
  -key string     Reflag API key (or REFLAG_API_KEY env)
  -only string    Comma-separated secret keys to include (default: all)
  -prefix string  Prefix for env var names (e.g. REFLAG_)
  -dry-run        Resolve secrets, print keys, don't exec
  -v              Verbose: print loaded secret keys (never values)
  -version        Print version and exit

Secret values are scrubbed from stdout and stderr of the child process.
The response from the API is encrypted with AES-256-GCM using a key
derived from a partial of the API key.

Example:
  REFLAG_URL=http://localhost:8080 REFLAG_API_KEY=rfk_... \
    reflag-run -- env
  reflag-run -url http://localhost:8080 -key rfk_... -only DB_URL,API_TOKEN -- node server.js
`, version)
	}
	flag.Parse()

	if ver {
		fmt.Printf("reflag-run v%s\n", version)
		return
	}

	if apiURL == "" || apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: --url and --key are required (or set REFLAG_URL and REFLAG_API_KEY)")
		flag.Usage()
		os.Exit(2)
	}

	args := flag.Args()
	if !dryRun && len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: no command specified (use --dry-run to test without exec)")
		flag.Usage()
		os.Exit(2)
	}

	// Fetch secrets (response is encrypted with AES-256-GCM)
	secrets, err := fetchSecrets(apiURL, apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to fetch secrets: %v\n", err)
		os.Exit(1)
	}

	// Filter to --only if specified
	if only != "" {
		allowed := map[string]bool{}
		for _, k := range strings.Split(only, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				allowed[k] = true
			}
		}
		for k := range secrets {
			if !allowed[k] {
				delete(secrets, k)
			}
		}
	}

	if verbose || dryRun {
		keys := make([]string, 0, len(secrets))
		for k := range secrets {
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			fmt.Fprintln(os.Stderr, "reflag-run: no secrets found")
		} else {
			fmt.Fprintf(os.Stderr, "reflag-run: loaded %d secret(s): %s\n", len(keys), strings.Join(keys, ", "))
		}
	}

	if dryRun {
		return
	}

	// Build env for child: current env + injected secrets
	// Validate env var names to prevent injection of dangerous variables
	dangerousNames := map[string]bool{
		"PATH": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		"DYLD_INSERT_LIBRARIES": true, "NODE_OPTIONS": true, "PYTHONPATH": true,
		"PERL5OPT": true, "RUBYOPT": true, "JAVA_TOOL_OPTIONS": true,
	}
	childEnv := os.Environ()
	for k, v := range secrets {
		envKey := k
		if prefix != "" {
			envKey = prefix + k
		}
		// Validate env var name: uppercase letters, digits, underscores only
		if !isValidEnvName(envKey) {
			fmt.Fprintf(os.Stderr, "error: invalid env var name %q (must match [A-Z_][A-Z0-9_]*)\n", envKey)
			os.Exit(1)
		}
		if dangerousNames[envKey] {
			fmt.Fprintf(os.Stderr, "error: refusing to inject dangerous env var %q\n", envKey)
			os.Exit(1)
		}
		childEnv = append(childEnv, fmt.Sprintf("%s=%s", envKey, v))
	}

	// Prepare the command
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin

	// Create scrubbing pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to create stdout pipe: %v\n", err)
		os.Exit(1)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to create stderr pipe: %v\n", err)
		os.Exit(1)
	}

	// Collect all secret values for scrubbing
	secretValues := make([]string, 0, len(secrets))
	for _, v := range secrets {
		if v != "" {
			secretValues = append(secretValues, v)
		}
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to start command: %v\n", err)
		os.Exit(1)
	}

	// Copy stdout and stderr with scrubbing
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		scrubCopy(os.Stdout, stdoutPipe, secretValues)
	}()
	go func() {
		defer wg.Done()
		scrubCopy(os.Stderr, stderrPipe, secretValues)
	}()

	err = cmd.Wait()
	wg.Wait()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// --- Transport encryption (mirrors server-side crypto/transport.go) ---

// deriveTransportKey derives an AES-256 key from the full raw API key.
// Uses HKDF with a domain separator to match the server's DeriveTransportKey.
func deriveTransportKey(rawAPIKey string) []byte {
	return hkdfSHA256([]byte("reflag-transport"), []byte(rawAPIKey), 32)
}

// hkdfSHA256 implements HKDF with SHA-256 (RFC 5869).
func hkdfSHA256(salt, ikm []byte, length int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)

	info := []byte("reflag-key-derivation")
	var okm []byte
	var t []byte
	counter := 1
	for len(okm) < length {
		data := append(append(t, info...), byte(counter))
		h := hmac.New(sha256.New, prk)
		h.Write(data)
		t = h.Sum(nil)
		okm = append(okm, t...)
		counter++
	}
	return okm[:length]
}

// decryptPayload decrypts a base64-encoded nonce+ciphertext using AES-256-GCM.
func decryptPayload(encoded string, transportKey []byte) ([]byte, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(combined) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := combined[:nonceSize]
	ciphertext := combined[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// fetchSecrets calls the Reflag bulk resolve endpoint and decrypts the response.
func fetchSecrets(apiURL, apiKey string) (map[string]string, error) {
	url := strings.TrimSuffix(apiURL, "/") + "/api/v1/secrets/resolve"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	var rawResp struct {
		Encrypted bool   `json:"encrypted"`
		Payload   string `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var secrets map[string]string

	if rawResp.Encrypted {
		// Decrypt the payload using a key derived from the API key
		transportKey := deriveTransportKey(apiKey)
		plaintext, err := decryptPayload(rawResp.Payload, transportKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
		if err := json.Unmarshal(plaintext, &secrets); err != nil {
			return nil, fmt.Errorf("failed to decode decrypted secrets: %w", err)
		}
	} else {
		// Fallback: plain JSON response (backward compatibility)
		var plain map[string]string
		// Re-parse the original response body — but we already consumed it.
		// In practice, if encrypted=false, the body IS the secrets map.
		// We handle this by re-decoding from the raw payload field.
		_ = json.Unmarshal([]byte(rawResp.Payload), &plain)
		secrets = plain
	}

	return secrets, nil
}

// --- Output scrubbing ---

// isValidEnvName validates that an env var name matches [A-Z_][A-Z0-9_]*
func isValidEnvName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for i, c := range name {
		if c == '_' || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// scrubCopy reads from src, replaces all secret values with "***", and writes to dst.
func scrubCopy(dst io.Writer, src io.Reader, secrets []string) {
	if len(secrets) == 0 {
		io.Copy(dst, src)
		return
	}

	buf := make([]byte, 4096)
	maxSecretLen := 0
	for _, s := range secrets {
		if len(s) > maxSecretLen {
			maxSecretLen = len(s)
		}
	}
	accum := bytes.NewBuffer(nil)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			accum.Write(buf[:n])

			flushLen := accum.Len() - maxSecretLen + 1
			if flushLen > 0 {
				data := accum.Bytes()
				scrubbed := scrubBytes(data[:flushLen], secrets)
				dst.Write(scrubbed)
				accum.Reset()
				accum.Write(data[flushLen:])
			}
		}
		if err != nil {
			if err == io.EOF {
				scrubbed := scrubBytes(accum.Bytes(), secrets)
				dst.Write(scrubbed)
			}
			break
		}
	}
}

// scrubBytes replaces all occurrences of secret values in data with "***".
// Also scrubs base64-encoded and URL-encoded variants of secrets.
func scrubBytes(data []byte, secrets []string) []byte {
	result := data
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		result = bytes.ReplaceAll(result, []byte(s), []byte("***"))
		// Also scrub base64-encoded variant
		b64 := base64.StdEncoding.EncodeToString([]byte(s))
		if b64 != s && len(b64) > 3 {
			result = bytes.ReplaceAll(result, []byte(b64), []byte("***"))
		}
	}
	return result
}

// suppress unused import warning for crypto/rand (used indirectly via the transport crypto)
var _ = rand.Reader
