package deps

import (
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const noScore = "점수 없음"

// severityOf maps the highest CVSS base score among a vulnerability's
// severity vectors to a severity bucket. The second value is a display memo.
func severityOf(v *osvschema.Vulnerability) (finding.Severity, string) {
	best := -1.0
	for _, s := range v.GetSeverity() {
		if score, ok := cvssScore(s.GetScore()); ok && score > best {
			best = score
		}
	}
	if best < 0 {
		return finding.Medium, noScore
	}
	memo := fmt.Sprintf("CVSS %.1f", best)
	switch {
	case best >= 9.0:
		return finding.Critical, memo
	case best >= 7.0:
		return finding.High, memo
	case best >= 4.0:
		return finding.Medium, memo
	default:
		return finding.Low, memo
	}
}

func cvssScore(vector string) (float64, bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		c, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.Score(), true
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		c, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		c, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	case strings.HasPrefix(vector, "AV:"):
		c, err := gocvss20.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	}
	return 0, false
}
