// toss-webhook-check는 토스페이먼츠 테스트 웹훅을 받아서, 보안 키를
// "문자열 그대로" 쓴 경우와 "16진수로 디코딩해서" 쓴 경우 중 어느 쪽이
// tosspayments-webhook-signature 헤더와 맞는지 알려 주는 확인용 프로그램이다.
//
// 서명 계산 방법은 토스페이먼츠 공식 문서를 따른다.
// https://docs.tosspayments.com/reference/using-api/webhook-events.md
//
//	HMAC-SHA256("{웹훅 본문}:{tosspayments-webhook-transmission-time}", 보안 키)
//	== base64 디코딩한 "v1:" 뒤의 값 (여러 개면 하나라도 일치)
//
// 보안 키는 환경 변수 TOSS_SECURITY_KEY로만 받고, 화면이나 파일에 쓰지 않는다.
// 테스트 상점의 보안 키로만 쓴다.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// result는 키를 쓰는 방식 하나에 대한 확인 결과다.
type result struct {
	Name  string
	Match bool
	Err   string
}

// check는 본문, 발송 시각, 서명 헤더, 보안 키로 두 가지 방식을 모두 확인한다.
func check(body []byte, transmissionTime, signatureHeader, securityKey string) []result {
	sigs := parseSignatures(signatureHeader)
	msg := append(append(append([]byte{}, body...), ':'), []byte(transmissionTime)...)

	out := []result{{Name: "보안 키를 문자열 그대로 사용"}}
	out[0].Match = anyMatch(hmacSHA256([]byte(securityKey), msg), sigs)

	hexRes := result{Name: "보안 키를 16진수로 디코딩해서 사용"}
	if raw, err := hex.DecodeString(securityKey); err != nil {
		hexRes.Err = "보안 키가 16진수 문자열이 아니어서 이 방식은 확인할 수 없음"
	} else {
		hexRes.Match = anyMatch(hmacSHA256(raw, msg), sigs)
	}
	return append(out, hexRes)
}

// parseSignatures는 "v1:AAA=,v1:BBB=" 형식에서 base64 디코딩한 값들을 돌려준다.
func parseSignatures(header string) [][]byte {
	var sigs [][]byte
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "v1:") {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(part, "v1:")); err == nil {
			sigs = append(sigs, b)
		}
	}
	return sigs
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func anyMatch(sum []byte, sigs [][]byte) bool {
	for _, s := range sigs {
		if hmac.Equal(sum, s) {
			return true
		}
	}
	return false
}

func main() {
	addr := flag.String("addr", ":8080", "웹훅을 받을 주소")
	flag.Parse()

	key := strings.TrimSpace(os.Getenv("TOSS_SECURITY_KEY"))
	if key == "" {
		fmt.Fprintln(os.Stderr, "환경 변수 TOSS_SECURITY_KEY에 테스트 상점의 보안 키를 넣고 다시 실행하세요.")
		os.Exit(2)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		sig := r.Header.Get("tosspayments-webhook-signature")
		tt := r.Header.Get("tosspayments-webhook-transmission-time")

		fmt.Println("────────────────────────────────────────")
		fmt.Printf("웹훅을 받았습니다 (%s %s, 본문 %d바이트)\n", r.Method, r.URL.Path, len(body))
		if sig == "" || tt == "" {
			fmt.Println("서명 헤더나 발송 시각 헤더가 없습니다. 이 웹훅으로는 확인할 수 없습니다.")
			fmt.Printf("  tosspayments-webhook-signature 있음: %v\n", sig != "")
			fmt.Printf("  tosspayments-webhook-transmission-time 있음: %v\n", tt != "")
		} else {
			fmt.Printf("서명 %d개, 발송 시각 %s\n", len(parseSignatures(sig)), tt)
			for _, res := range check(body, tt, sig, key) {
				switch {
				case res.Err != "":
					fmt.Printf("  %s: %s\n", res.Name, res.Err)
				case res.Match:
					fmt.Printf("  %s: ✅ 일치\n", res.Name)
				default:
					fmt.Printf("  %s: ❌ 불일치\n", res.Name)
				}
			}
		}
		// 토스페이먼츠는 10초 안에 200 응답을 받아야 재전송하지 않는다.
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("웹훅을 기다리는 중입니다: http://localhost%s/ (끝내려면 Ctrl+C)\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
