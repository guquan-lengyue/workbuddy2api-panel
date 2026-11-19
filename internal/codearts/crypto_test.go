package codearts

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestSignRequestVector(t *testing.T) {
	body := []byte(`{"model":"GLM-5.2","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	headers := map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "text/event-stream",
		"x-auth-token":    "TOKEN",
		"x-snap-traceid":  "trace123",
		"X-Language":      "zh-cn",
		"app-id":          "CodeAgent3.0",
		"is_confidential": "false",
	}
	out, err := SignRequest("POST",
		"https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions",
		headers, body, "AKID", "SECRETKEY", "TOKEN", "20261031T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	want := "SDK-HMAC-SHA256 Access=AKID, SignedHeaders=accept;app-id;content-type;host;" +
		"is_confidential;x-auth-token;x-language;x-sdk-content-sha256;x-sdk-date;" +
		"x-security-token;x-snap-traceid, Signature=" +
		"28c9c49de88825070ab6fba37f9b30a44bc22f165743bb6c409338cb5b78ad09"
	if out["Authorization"] != want {
		t.Fatalf("Authorization mismatch:\n got %s\nwant %s", out["Authorization"], want)
	}
	if out["Host"] != "snap-access.cn-north-4.myhuaweicloud.com" {
		t.Fatalf("Host = %q", out["Host"])
	}
	if out["X-Sdk-Date"] != "20261031T000000Z" {
		t.Fatalf("date = %q", out["X-Sdk-Date"])
	}
	if out["X-Security-Token"] != "TOKEN" {
		t.Fatalf("security token = %q", out["X-Security-Token"])
	}
	sum := sha256.Sum256(body)
	if out["X-Sdk-Content-Sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("payload hash = %q", out["X-Sdk-Content-Sha256"])
	}
}

func TestDPoPAndJWKRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	jwk := PrivateJWK(key)
	if jwk["d"] == "" || jwk["x"] == "" || jwk["y"] == "" {
		t.Fatalf("incomplete JWK: %#v", jwk)
	}
	restored, err := KeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if restored.D.Cmp(key.D) != 0 || restored.X.Cmp(key.X) != 0 || restored.Y.Cmp(key.Y) != 0 {
		t.Fatal("JWK round trip mismatch")
	}
	proof, err := DPoPProof(key, "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof parts = %d", len(parts))
	}
	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(head, &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["typ"] != "dpop+jwt" {
		t.Fatalf("header = %#v", header)
	}
	public, _ := header["jwk"].(map[string]any)
	if public["d"] != nil {
		t.Fatal("public JWK leaks private scalar")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["htm"] != "POST" || claims["htu"] != "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens" {
		t.Fatalf("claims = %#v", claims)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("DPoP signature did not verify")
	}
}
