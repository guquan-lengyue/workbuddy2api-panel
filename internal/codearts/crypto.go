package codearts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SigningAlgorithm is the Huawei Cloud request signing algorithm.
const SigningAlgorithm = "SDK-HMAC-SHA256"

func b64url(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func b64urlDecode(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	pad := strings.Repeat("=", (4-len(text)%4)%4)
	return base64.URLEncoding.DecodeString(text + pad)
}

func intBytes(v *big.Int, size int) []byte {
	out := make([]byte, size)
	v.FillBytes(out)
	return out
}

// GenerateKey creates a P-256 key for DPoP.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicJWK returns the public JWK advertised in the DPoP header.
func PublicJWK(key *ecdsa.PrivateKey) map[string]string {
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64url(intBytes(key.PublicKey.X, 32)),
		"y":   b64url(intBytes(key.PublicKey.Y, 32)),
	}
}

// PrivateJWK returns the persisted JWK including the private scalar.
func PrivateJWK(key *ecdsa.PrivateKey) map[string]string {
	out := PublicJWK(key)
	out["d"] = b64url(intBytes(key.D, 32))
	return out
}

// KeyFromJWK restores a P-256 key from a persisted JWK and validates that the
// public point matches the private scalar.
func KeyFromJWK(jwk map[string]string) (*ecdsa.PrivateKey, error) {
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		return nil, fmt.Errorf("invalid DPoP JWK curve")
	}
	dBytes, err := b64urlDecode(jwk["d"])
	if err != nil || len(dBytes) == 0 {
		return nil, fmt.Errorf("invalid DPoP JWK private scalar")
	}
	xBytes, err := b64urlDecode(jwk["x"])
	if err != nil {
		return nil, fmt.Errorf("invalid DPoP JWK x")
	}
	yBytes, err := b64urlDecode(jwk["y"])
	if err != nil {
		return nil, fmt.Errorf("invalid DPoP JWK y")
	}
	d := new(big.Int).SetBytes(dBytes)
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid DPoP JWK private scalar")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid DPoP JWK public point")
	}
	// The public point is verified above; also check that d*G equals it.
	wx, wy := curve.ScalarBaseMult(d.Bytes())
	if wx.Cmp(x) != 0 || wy.Cmp(y) != 0 {
		return nil, fmt.Errorf("DPoP JWK public/private key mismatch")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func signES256(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// DPoPProof builds a DPoP JWT for a token endpoint (htm=POST, htu=URL).
func DPoPProof(key *ecdsa.PrivateKey, htu string) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": PublicJWK(key),
	}
	payload := map[string]any{
		"htm": "POST",
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": RandomHex(16),
	}
	head, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64url(head) + "." + b64url(body)
	sig, err := signES256(key, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(sig), nil
}

// PKCEPair returns a verifier and its S256 challenge.
func PKCEPair() (verifier, challenge string, err error) {
	raw := make([]byte, 64)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	verifier = b64url(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = b64url(sum[:])
	return verifier, challenge, nil
}

// RandomHex returns n random bytes encoded as hex.
func RandomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand failure is fatal for OAuth; callers treat an empty value
		// as an error where it matters.
		return ""
	}
	return hex.EncodeToString(raw)
}

func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalURI(path string) string {
	if path == "" {
		path = "/"
	}
	segs := strings.Split(path, "/")
	for i := range segs {
		segs[i] = percentEncode(segs[i])
	}
	out := strings.Join(segs, "/")
	if !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
}

type queryPair struct{ k, v string }

func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	var pairs []queryPair
	for k, vs := range values {
		for _, v := range vs {
			pairs = append(pairs, queryPair{k: k, v: v})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(percentEncode(p.k))
		b.WriteByte('=')
		b.WriteString(percentEncode(p.v))
	}
	return b.String()
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// SignRequest adds Huawei Cloud SDK-HMAC-SHA256 headers to a copy of headers.
// The input map is not modified.
func SignRequest(method, rawURL string, headers map[string]string, body []byte, accessKey, secretKey, securityToken, xDate string) (map[string]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(headers)+5)
	for k, v := range headers {
		out[k] = v
	}
	if xDate == "" {
		xDate = time.Now().UTC().Format("20060102T150405Z")
	}
	out["X-Sdk-Date"] = xDate
	out["Host"] = u.Host
	if securityToken != "" {
		out["X-Security-Token"] = securityToken
	}
	payloadHash := sha256Hex(body)
	out["X-Sdk-Content-Sha256"] = payloadHash

	lower := make(map[string]string, len(out))
	for k, v := range out {
		lower[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	keys := make([]string, 0, len(lower))
	for k := range lower {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonicalHeaders strings.Builder
	for _, k := range keys {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(lower[k])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(keys, ";")
	canonicalRequest := strings.Join([]string{
		strings.ToUpper(method),
		canonicalURI(u.Path),
		canonicalQuery(u.RawQuery),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	stringToSign := strings.Join([]string{
		SigningAlgorithm,
		xDate,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))
	out["Authorization"] = SigningAlgorithm +
		" Access=" + accessKey +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + signature
	return out, nil
}
