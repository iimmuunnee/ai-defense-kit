// Package kev reads the CISA Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultURL is the public mirror of the CISA KEV catalog.
const DefaultURL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

const maxBody = 32 << 20

// Catalog is a set of CVE IDs known to be exploited in the wild.
type Catalog struct{ ids map[string]struct{} }

// Parse reads the KEV JSON format (top-level vulnerabilities[].cveID).
func Parse(r io.Reader) (*Catalog, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxBody)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("KEV 목록을 해석하지 못했습니다: %w", err)
	}
	c := &Catalog{ids: make(map[string]struct{}, len(doc.Vulnerabilities))}
	for _, v := range doc.Vulnerabilities {
		if v.CVEID != "" {
			c.ids[strings.ToUpper(v.CVEID)] = struct{}{}
		}
	}
	return c, nil
}

// Fetch downloads and parses the catalog from url.
func Fetch(ctx context.Context, c *http.Client, url string) (*Catalog, error) {
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV 목록 요청 실패: HTTP %d", resp.StatusCode)
	}
	return Parse(resp.Body)
}

// Has reports whether cveID is in the catalog.
func (c *Catalog) Has(cveID string) bool {
	if c == nil {
		return false
	}
	_, ok := c.ids[strings.ToUpper(cveID)]
	return ok
}
