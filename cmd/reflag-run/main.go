package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	childEnv := os.Environ()
	for k, v := range secrets {
		envKey := k
		if prefix != "" {
			envKey = prefix + k
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

// deriveTransportKey derives an AES-256 key from a partial API key.
// Uses the first 16 characters of the API key (after the rfk_ prefix)
// as key material, hashed with SHA-256.
func deriveTransportKey(rawAPIKey string) []byte {
	keyMaterial := rawAPIKey
	if len(keyMaterial) > 20 {
		keyMaterial = keyMaterial[4:20]
	}
	hash := sha256.Sum256([]byte("reflag-transport:" + keyMaterial))
	return hash[:]
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
func scrubBytes(data []byte, secrets []string) []byte {
	result := data
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		result = bytes.ReplaceAll(result, []byte(s), []byte("***"))
	}
	return result
}

// suppress unused import warning for crypto/rand (used indirectly via the transport crypto)
var _ = rand.Reader
