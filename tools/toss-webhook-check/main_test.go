package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func sign(key, body []byte, tt string) string {
	m := hmac.New(sha256.New, key)
	m.Write(append(append(append([]byte{}, body...), ':'), tt...))
	return "v1:" + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func TestCheckRawKey(t *testing.T) {
	key := "00112233" + "445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	body := []byte(`{"status":"DONE"}`)
	tt := "2024-09-05T12:19:21+09:00"
	hdr := "v1:AAAA," + sign([]byte(key), body, tt) // 두 번째 서명이 맞는 경우
	res := check(body, tt, hdr, key)
	if !res[0].Match || res[1].Match {
		t.Fatalf("raw key should match only the raw variant: %+v", res)
	}
}

func TestCheckHexKey(t *testing.T) {
	key := "00112233" + "445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	raw, _ := hex.DecodeString(key)
	body := []byte(`{"status":"DONE"}`)
	tt := "2024-09-05T12:19:21+09:00"
	res := check(body, tt, sign(raw, body, tt), key)
	if res[0].Match || !res[1].Match {
		t.Fatalf("hex key should match only the hex variant: %+v", res)
	}
}

func TestCheckNonHexKey(t *testing.T) {
	res := check([]byte("x"), "t", "v1:AAAA", "not-hex")
	if res[1].Err == "" {
		t.Fatalf("non-hex key must report an error for the hex variant: %+v", res)
	}
}

func TestParseSignaturesSkipsBad(t *testing.T) {
	if got := parseSignatures("v1:AAAA, v2:BBBB, v1:!!!"); len(got) != 1 {
		t.Fatalf("want 1 valid v1 signature, got %d", len(got))
	}
}
