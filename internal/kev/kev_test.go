package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestKEVParse(t *testing.T) {
	f, err := os.Open("../../testdata/kev/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Has("CVE-2021-44228") || !c.Has("cve-2022-22965") {
		t.Error("known CVEs should be present")
	}
	if c.Has("CVE-0000-0000") {
		t.Error("unknown CVE should be absent")
	}
}

func TestKEVParseInvalid(t *testing.T) {
	if _, err := Parse(strings.NewReader("not json")); err == nil {
		t.Error("expected error")
	}
}

func TestKEVNilCatalog(t *testing.T) {
	var c *Catalog
	if c.Has("CVE-2021-44228") {
		t.Error("nil catalog has nothing")
	}
}

func TestKEVFetch(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "../../testdata/kev/sample.json")
	}))
	defer ok.Close()
	c, err := Fetch(context.Background(), ok.Client(), ok.URL)
	if err != nil || !c.Has("CVE-2021-44228") {
		t.Fatalf("fetch: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "x", 500)
	}))
	defer bad.Close()
	if _, err := Fetch(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Error("expected HTTP error")
	}
}
