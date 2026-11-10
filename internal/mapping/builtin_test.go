package mapping_test

import (
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/rules"
)

func TestBuiltinMappingIDsExist(t *testing.T) {
	cat, err := mapping.Load(aidefensekit.Data)
	if err != nil {
		t.Fatalf("mapping.Load: %v", err)
	}
	rs, err := rules.Load(aidefensekit.Data)
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	for _, r := range rs {
		for _, id := range r.Mappings {
			if _, ok := cat.Item(id); !ok {
				t.Errorf("규칙 %s의 매핑 ID %s가 mappings/에 없음", r.ID, id)
			}
		}
	}
}

func loadBuiltin(t *testing.T) mapping.Catalog {
	t.Helper()
	cat, err := mapping.Load(aidefensekit.Data)
	if err != nil {
		t.Fatalf("mapping.Load: %v", err)
	}
	return cat
}

// 설계 문서 7.7절의 목표는 15~20개다. 원문이 직접 뒷받침하는 연결만 남기니 14개가 되어
// 하한을 14로 낮췄다. 항목 수를 맞추려고 약한 연결을 넣는 것보다 보수적인 연결이 낫다
// (근거: docs/research/2026-11-04-standards-facts.md 5·6절).
func TestBuiltinMappingCount(t *testing.T) {
	if n := loadBuiltin(t).Len(); n < 14 || n > 20 {
		t.Fatalf("내장 기준 항목 수 = %d, 14 이상 20 이하여야 함", n)
	}
}

// 설계 문서 7.7절: 첫 버전은 모든 항목을 원문 대조(checked)한 상태로 배포한다.
func TestBuiltinMappingsChecked(t *testing.T) {
	cat := loadBuiltin(t)
	for _, id := range builtinItemIDs(t) {
		it, ok := cat.Item(id)
		if !ok {
			t.Fatalf("항목 %s를 읽지 못함", id)
		}
		if it.Review.Status != mapping.StatusChecked {
			t.Errorf("%s: review.status = %q, checked여야 함", id, it.Review.Status)
		}
		if it.Review.Quote == "" || it.Clause == "" || it.SummaryKo == "" {
			t.Errorf("%s: quote, clause, summary_ko가 모두 있어야 함", id)
		}
	}
}

// builtinItemIDs lists item IDs from the embedded file names (mappings/<dir>/<ID>.yaml).
func builtinItemIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	err := fs.WalkDir(aidefensekit.Data, "mappings", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path.Ext(p) != ".yaml" || p == "mappings/kinds.yaml" {
			return nil
		}
		ids = append(ids, strings.TrimSuffix(path.Base(p), ".yaml"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// 원문이 뒷받침하지 않아 일부러 연결하지 않은 종류와 그 이유.
// 근거: docs/research/2026-11-04-standards-facts.md
var unlinkedKinds = map[string]string{
	"PH-001":        "PHP 공통 취약 코드 결과다. 원문과 대조한 국내 기준 항목 중 이 내용을 직접 다루는 것이 없어 연결하지 않았다",
	"PH-002":        "PHP 공통 취약 코드 결과다. 원문과 대조한 국내 기준 항목 중 이 내용을 직접 다루는 것이 없어 연결하지 않았다",
	"PH-003":        "PHP 공통 취약 코드 결과다. 원문과 대조한 국내 기준 항목 중 이 내용을 직접 다루는 것이 없어 연결하지 않았다",
	"PH-004":        "PHP 공통 취약 코드 결과다. 원문과 대조한 국내 기준 항목 중 이 내용을 직접 다루는 것이 없어 연결하지 않았다",
	"PH-005":        "PHP 공통 취약 코드 결과다. 원문과 대조한 국내 기준 항목 중 이 내용을 직접 다루는 것이 없어 연결하지 않았다",
	"WEB-001":       "integrity 없는 외부 스크립트를 알리는 참고(낮음) 결과다. 국내 기준 항목이 스크립트 무결성 표기를 직접 다루는지 확인하지 못했다",
	"WL-001":        "지갑 코드의 개인 키 직접 읽기를 알리는 의심 결과다. 국내 기준 항목이 이를 직접 다루는지 확인하지 못해 연결하지 않았다",
	"WL-002":        "요청 본문이나 외부 응답이 서명 함수에 들어가는 코드를 알리는 의심 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WL-003":        "EIP-7702 위임 서명 사용을 알리는 검토 대상(낮음) 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"RE-002":        "공개를 전제로 한 키도 걸리는 의심 결과다. 비밀 값으로 확인되지 않아 암호키 관리 항목에 연결하지 않았다",
	"RE-003":        "참고(낮음) 결과다. 쓴 곳만 찾고 넣는 값을 따라가지 않아 입력값 검증 항목에 연결할 근거가 없다",
	"NX-001":        "참고(낮음) 결과다. 미들웨어에서 인증을 확인하는 것 자체는 문제가 아니며, 원문 항목 중 '미들웨어만으로 확인함'을 직접 다루는 것이 없다",
	"malicious-lib": "악성 패키지를 알리는 결과다. 국내 기준 항목이 악성 패키지를 직접 다루는지 확인하지 못했다",
	"AR-001":        "받은 저장소의 자동 실행 설정을 알리는 결과다. 국내 기준 항목이 이 동작을 직접 다루지 않는다",
	"AR-002":        "받은 저장소의 자동 실행 설정을 알리는 결과다. 국내 기준 항목이 이 동작을 직접 다루지 않는다",
	"AR-003":        "받은 저장소의 자동 실행 설정을 알리는 결과다. 국내 기준 항목이 이 동작을 직접 다루지 않는다",
	"AR-004":        "받은 저장소의 자동 실행 설정을 알리는 결과다. 국내 기준 항목이 이 동작을 직접 다루지 않는다",
	"AR-005":        "받은 저장소의 자동 실행 설정을 알리는 결과다. 국내 기준 항목이 이 동작을 직접 다루지 않는다",
	"AR-006":        "받은 저장소에 결과를 숨길 수 있는 설정 파일이 있음을 알리는 결과다. 국내 기준 항목이 이 동작을 직접 다루지 않는다",
	"CI-001":        "워크플로에 장기 클라우드 키를 둔 설정을 알리는 결과다. 국내 기준 항목이 CI 설정의 키 사용을 직접 다루지 않는다",
	"CI-002":        "커밋 해시로 고정하지 않은 액션을 알리는 결과다. 국내 기준 항목이 CI 액션의 버전 고정을 직접 다루지 않는다",
	"CI-003":        "GITHUB_TOKEN 권한 설정을 알리는 결과다. 국내 기준 항목이 CI 토큰 권한을 직접 다루지 않는다",
	"CI-004":        "pull_request_target에서 풀 리퀘스트 코드를 내려받는 워크플로를 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"CI-005":        "워크플로 파일이나 폴더를 읽지 못했음을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-001":        "감시 중인 지갑의 위임 변경을 알리는 결과다. 국내 기준 항목이 지갑 권한 변경 감시를 직접 다루지 않는다",
	"WA-002":        "감시 중인 지갑의 소유자·임계값·관리자·로직 컨트랙트, XRPL 계정의 레귤러 키·서명자 목록·플래그 변경을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-003":        "감시 중인 주소의 코드 변경을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-004":        "RPC 응답 불일치를 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-005":        "위임이 허용 목록 안의 주소로 바뀌었음을 알리는 정보 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-006":        "기준값에 있던 위임이 지워졌음을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-007":        "기준값이 설정과 다른 대상을 설명함을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-101":        "배포된 웹 스크립트가 기준값과 달라졌음을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-102":        "저장소의 빌드·편집기 설정 파일이 기준값과 달라졌음을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"WA-103":        "실행 중인 컨테이너 이미지가 기준값과 달라졌음을 알리는 결과다. 국내 기준 항목이 이를 직접 다루지 않는다",
	"DV-001":        "개발자 컴퓨터의 kubeconfig에 저장된 고정 토큰·클라이언트 키를 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 도구 설정 파일을 직접 다루지 않는다",
	"DV-002":        "개발자 컴퓨터의 Docker 설정에 저장된 레지스트리 인증 값을 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 도구 설정 파일을 직접 다루지 않는다",
	"DV-003":        "개발자 컴퓨터에 저장된 AWS 장기 키를 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 도구 설정 파일을 직접 다루지 않는다",
	"DV-004":        "개발자 컴퓨터의 gh 설정 파일에 평문으로 저장된 토큰을 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 도구 설정 파일을 직접 다루지 않는다",
	"DV-101":        "개발자 컴퓨터의 개발 도구 실행 파일이 기준값과 달라졌음을 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 도구 실행 파일을 직접 다루지 않는다",
	"DV-102":        "개발자 컴퓨터의 Homebrew 링크가 Homebrew 밖을 가리킴을 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 도구 실행 파일을 직접 다루지 않는다",
	"DV-103":        "개발자 컴퓨터의 자동 실행 지점이 기준값과 달라졌음을 알리는 결과다. 국내 기준 항목이 개인 컴퓨터의 자동 실행 설정을 직접 다루지 않는다",
	"DV-201":        "개인 컴퓨터의 글 파일에 지갑 시드 문구로 보이는 것이 적혀 있음을 알리는 결과다. 국내 기준 항목이 개인의 지갑 복구 문구 보관을 직접 다루지 않는다",
	"DV-202":        "개인 컴퓨터의 브라우저에 지갑 확장 프로그램 저장소가 있음을 알리는 목록 결과다. 국내 기준 항목이 개인 컴퓨터의 지갑 프로그램을 직접 다루지 않는다",
	"DV-203":        "개인 컴퓨터에 데스크톱 지갑의 키 저장 파일이 있음을 알리는 목록 결과다. 국내 기준 항목이 개인 컴퓨터의 지갑 프로그램을 직접 다루지 않는다",
	"DV-204":        "개인 컴퓨터에 잠그지 않고 저장하는 것이 기본인 키 파일이 있음을 알리는 결과다. 파일을 열지 않아 키가 들어 있는지 확인하지 않으므로 암호키 관리 항목에 연결하지 않았다",
}

func TestBuiltinKindsLinked(t *testing.T) {
	cat := loadBuiltin(t)
	rs, err := rules.Load(aidefensekit.Data)
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	linked := map[string]bool{}
	var kinds []string
	for _, r := range rs {
		kinds = append(kinds, r.ID)
		if len(r.Mappings) > 0 {
			linked[r.ID] = true
		}
	}
	for _, k := range mapping.BuiltinKinds {
		kinds = append(kinds, k)
		got := []finding.Finding{{ID: k, Kind: k}}
		cat.Attach(got)
		if len(got[0].Mappings) > 0 {
			linked[k] = true
		}
	}
	for _, k := range kinds {
		reason, allowed := unlinkedKinds[k]
		switch {
		case linked[k] && allowed:
			t.Errorf("%s: 기준이 연결되었으니 허용 목록에서 빼야 함 (%s)", k, reason)
		case !linked[k] && !allowed:
			t.Errorf("%s: 연결된 국내 기준이 없음 (연결하지 않을 이유가 있으면 허용 목록에 적을 것)", k)
		}
	}
	for k := range unlinkedKinds {
		if !slices.Contains(kinds, k) {
			t.Errorf("허용 목록의 %s는 규칙이나 내장 종류가 아님", k)
		}
	}
}
