package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/safeio"
)

const baselineVersion = 1

// Baseline is the saved state that later observations are compared with.
type Baseline struct {
	Version   int                    `json:"version"`
	CreatedAt time.Time              `json:"created_at"`
	Entries   map[string]Observation `json:"entries"`
}

// LoadBaseline reads a baseline. A non-empty pinnedSHA256 must match the
// file's SHA-256 (hex, case-insensitive). A missing version or entries is an
// error, so a damaged file cannot read as an empty baseline.
func LoadBaseline(path, pinnedSHA256 string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("기준값 파일을 읽을 수 없습니다: %w", err)
	}
	if pinnedSHA256 != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(pinnedSHA256)) {
			return Baseline{}, fmt.Errorf("기준값 파일의 SHA-256이 지정한 값과 다릅니다")
		}
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, fmt.Errorf("기준값 파일 형식이 올바르지 않습니다: %w", err)
	}
	if b.Version != baselineVersion {
		return Baseline{}, fmt.Errorf("지원하지 않는 기준값 버전입니다: %d", b.Version)
	}
	if b.Entries == nil {
		return Baseline{}, fmt.Errorf("기준값 파일에 entries가 없습니다")
	}
	return b, nil
}

// Save writes the baseline as indented JSON via a temp file in the same
// directory and a rename, and returns the SHA-256 hex of the written bytes.
func (b Baseline) Save(path string) (string, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return "", fmt.Errorf("기준값을 만들 수 없습니다: %w", err)
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)

	if err := safeio.WriteFile(path, 0o600, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}); err != nil {
		return "", fmt.Errorf("기준값 파일을 저장할 수 없습니다: %w", err)
	}
	return hex.EncodeToString(sum[:]), nil
}

// encode returns the bytes Save writes and their SHA-256.
func (b Baseline) encode() ([]byte, [sha256.Size]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("기준값을 만들 수 없습니다: %w", err)
	}
	data = append(data, '\n')
	return data, sha256.Sum256(data), nil
}

// NewBaseline returns a baseline of the current version.
func NewBaseline(now time.Time, entries map[string]Observation) Baseline {
	if entries == nil {
		entries = map[string]Observation{}
	}
	return Baseline{Version: baselineVersion, CreatedAt: now, Entries: entries}
}

// SHA256 returns the hex SHA-256 of the bytes Save would write.
func (b Baseline) SHA256() (string, error) {
	_, sum, err := b.encode()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

// FileSHA256 returns the hex SHA-256 of the file's bytes.
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("기준값 파일을 읽을 수 없습니다: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
