# crt.sh output=json 조사 결과 (공식 소스: github.com/crtsh/certwatch_db)

조사 대상 커밋: f4a6bc75510d6abcb0caa6fc46883308c2a2a7ae (읽기 전용 클론으로 확인)
모든 경로는 저장소 루트 기준. 핵심 코드는 `fnc/web_apis.fnc`의 `web_apis()` 함수(PL/pgSQL).
`README.md`는 내용이 `# certwatch_db` / `Database schema` 두 줄뿐이다 (확인됨).

---

## 1. output=json 생성 방식과 필드명

### 1-1. JSON 출력 경로 (확인됨)
- fnc/web_apis.fnc:293 `t_outputType := coalesce(get_parameter('output', paramNames, paramValues), '');`
- fnc/web_apis.fnc:320-325 `IF (t_outputType = 'json') AND t_isJSONOutputSupported THEN` ... `Content-Type: application/json` / `Access-Control-Allow-Origin: *`
- fnc/web_apis.fnc:4877-4878 `IF t_outputType = 'json' THEN t_output := t_output || '[';`
- fnc/web_apis.fnc:4950-4952 `ELSIF t_outputType = 'json' THEN t_output := t_output || t_temp3 || row_to_json(l_record, FALSE); t_temp3 := ',';`
- fnc/web_apis.fnc:5233-5234 `ELSIF t_outputType = 'json' THEN t_output := t_output || ']';`
- 결론(확인됨): 응답은 최상위가 JSON 배열이며, 각 원소는 SQL 결과 행을 `row_to_json`으로 직렬화한 객체이다. 별도의 필드명 매핑 코드는 없고, SELECT 별칭이 곧 키 이름이다.
- 지원 검색 유형: Identity, Common Name, Email Address, Organizational Unit Name, Organization Name, Domain Name, Email Address (SAN), IP Address 등에서 `t_isJSONOutputSupported := TRUE` (fnc/web_apis.fnc:246-251).

### 1-2. Identity/dNSName 검색(group=none, 기본값) 시 SELECT 별칭 (확인됨)
- fnc/web_apis.fnc:4623-4625 `SELECT __issuer_ca_id_table__.ISSUER_CA_ID,` / `ca.NAME ISSUER_NAME,__common_name_field__` / `__name_value__ NAME_VALUE,`
- fnc/web_apis.fnc:4642-4650 `__cert_id_field__ ID,` ... `__not_before_field__,` `__not_after_field__,` `__serial_number_field__,` `__result_count_field__`
- fnc/web_apis.fnc:4753-4757 (ci CTE) `x509_commonName(sub.CERTIFICATE) COMMON_NAME,` / `x509_notBefore(...) NOT_BEFORE,` / `x509_notAfter(...) NOT_AFTER,` / `encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER,` / `count(sub.CERTIFICATE_ID)::bigint RESULT_COUNT`
- fnc/web_apis.fnc:4814-4815 `IF (coalesce(t_groupBy, '') = 'none') AND (t_type != 'Common Name') THEN t_commonName_field := ... 'ci.COMMON_NAME,'`
- fnc/web_apis.fnc:497 `t_groupBy := coalesce(get_parameter('group', paramNames, paramValues), 'none');` (lint 계열이 아니면 기본 group=none)
- 따라서 키(대문자 별칭 기준): ISSUER_CA_ID, ISSUER_NAME, COMMON_NAME, NAME_VALUE, ID, NOT_BEFORE, NOT_AFTER, SERIAL_NUMBER, RESULT_COUNT. (확인됨: 별칭 목록)
- 소문자 키(issuer_ca_id, issuer_name, common_name, name_value, id, not_before, not_after, serial_number, result_count)로 나오는 것은 PostgreSQL이 따옴표 없는 식별자를 소문자로 접는 동작에 근거한다. 저장소 코드에 직접 적힌 내용이 아니므로 확인 못 함(실제 응답 샘플로 검증 필요). 이 환경에서는 crt.sh가 차단되어 있어 샘플을 확인하지 못했다.
- `entry_timestamp`는 `CT Entry ID` 검색에서만 포함된다(확인됨): fnc/web_apis.fnc:4636-4637 `IF t_type = 'CT Entry ID' THEN t_entryTimestamp_field := 'ctle.ENTRY_TIMESTAMP';` 도메인(Identity) 검색 JSON에는 entry_timestamp가 없다.
- `common_name`은 `type=Common Name`(cn=) 검색에서는 생략된다(확인됨, fnc/web_apis.fnc:4814).
- `NOT_BEFORE`/`NOT_AFTER` 값의 직렬화 형식은 row_to_json의 timestamp 기본 형식에 의존하며 저장소에 형식 지정 코드가 없다 -> 형식은 확인 못 함.

### 1-3. name_value는 개행(\n) 구분 목록인가 (확인됨, 단 의미에 주의)
- fnc/web_apis.fnc:4753 `array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,`
- fnc/web_apis.fnc:4837 `t_nameValue := 'array_to_string(ci.NAME_VALUES, chr(10))';`
- 즉 name_value는 중복 제거된 값들을 `chr(10)`(LF)으로 이어 붙인 문자열이다. Go에서는 `strings.Split(v, "\n")`로 분리하면 된다.
- 주의(확인됨): 목록은 "인증서의 전체 SAN"이 아니라 "검색 조건에 일치한 identity 행"만 모은 것이다. 근거: ci CTE의 FROM은 `certificate_and_identities cai`(이름 속성 1개당 1행, sql/create_schema.sql:206-227)이고 WHERE에서 `cai.NAME_VALUE ILIKE ('%' || $1 || '%')` 등으로 행을 먼저 거른 뒤 `array_agg`한다(fnc/web_apis.fnc:4773-4796). 또 `NAME_VALUE`에는 subject 속성(CN, O 등)과 모든 SAN 종류(dNSName, rfc822Name, iPAddress ...)가 섞일 수 있다(sql/create_schema.sql:210-225, `'san:' || CASE TYPE_NUM WHEN 2 THEN 'dNSName' ...`). `q=` 검색(Identity)은 NAME_TYPE 필터가 없다(fnc/web_apis.fnc:4798 `IF t_type != 'Identity' THEN ... AND cai.NAME_TYPE = ...`). 따라서 서브도메인 목록용으로는 `dnsname=`(Domain Name, san:dNSName 한정) 또는 클라이언트 쪽 필터링이 필요하다.
- 와일드카드 SAN(`*.example.com`) 값이 그대로 name_value에 들어올 수 있다는 점은 코드상 값을 가공하지 않으므로 합리적 추론이나, 응답 샘플로는 확인하지 못했다(확인 못 함).

---

## 2. 쿼리 파라미터

### 2-1. 파라미터 이름 매핑 (확인됨)
- fnc/web_apis.fnc:47 `'identity', 'Identity', NULL,`
- fnc/web_apis.fnc:49 `'cn', 'Common Name', NULL,`
- fnc/web_apis.fnc:56 `'dnsname', 'Domain Name', NULL,` (그 다음 줄 `'domain', 'Domain Name'`)
- fnc/web_apis.fnc:62 `'q', 'ID', 'SHA-1(Certificate)', 'SHA-256(Certificate)', 'ChromiumNetLogSHA256SPKI', 'Identity', NULL,`
- `q`는 값이 위 유형들(숫자 ID, SHA-1/256 해시, sha256/... 형식)로 해석되면 그쪽으로 가고, 아니면 마지막 `Identity`로 폴백한다 (fnc/web_apis.fnc:199-285의 루프; 확인됨). 도메인 문자열은 `Identity`가 된다.
- 파라미터 이름 비교: fnc/get_parameter.fnc `t_parameter := lower(parameter);` 후 `IF paramNames[i] = t_parameter`. 코드가 질의 이름을 소문자화하지 않고 `paramNames[i]`와 비교하므로 전달되는 이름은 호출측(웹 프런트엔드, 저장소에 없음)에서 소문자로 넘길 것으로 보이나 그 부분은 확인 못 함. ~~실무에서는 소문자(`q`, `identity`, `cn`, `dnsname`)를 쓰는 것이 안전하다.~~ **(틀린 추정: 6절에서 실제 응답으로 확인한 결과, 소문자 `dnsname`은 오류가 나고 `dNSName`만 동작한다.)** 문서/HTML 폼은 `dNSName` 표기를 쓴다(fnc/web_apis.fnc:942 `<OPTION value="dNSName">`).
- 유형별 NAME_TYPE 필터 (확인됨): fnc/web_apis.fnc:428-429 `t_nameType := 'dNSName'; t_nameType_oid := 'san:dNSName';` / `Common Name`은 `'2.5.4.3'` (fnc/web_apis.fnc:419-420 부근). `Identity`는 필터 없음 (fnc/web_apis.fnc:413-414 `ELSIF t_type = 'Identity' THEN NULL;`).

### 2-2. match= 옵션과 와일드카드 (확인됨)
- fnc/web_apis.fnc:340-368:
  - `t_temp := upper(get_parameter('match', paramNames, paramValues));`
  - `ELSIF t_temp = 'ANY' THEN t_match := 'Any';` / `'SINGLE'` -> `'Single'` / `'ILIKE'` -> `'ILIKE'` / `'LIKE'` -> `'LIKE'` / `'FTS'` -> `'FTS'` / 그 외 -> `t_match := '=';`
- match 미지정 시 기본값 (fnc/web_apis.fnc:341-355):
  - 값에 `-`가 있으면 `'Single'`: `IF position('-' in coalesce(t_value, '')) > 0 THEN t_match := 'Single';`
  - 공백+`-`/`+`/` OR `/` AND ` 포함 -> `'Any'`; 공백 포함 -> `'Single'`; `%:*`로 끝나고 공백 없음 -> `'FTS'`; 그 외 `t_match := 'ILIKE';`
  - 주의: 하이픈이 든 도메인(예: `my-site.example.com`)은 기본이 ILIKE가 아니라 `Single`(전문검색)이 된다. 일관된 동작이 필요하면 `match=ILIKE`를 명시하는 편이 낫다(추론이 아니라 위 분기에서 도출됨).
- LIKE/ILIKE 의미론 (확인됨): fnc/web_apis.fnc:4783-4796
  - `'AND cai.NAME_VALUE ' || t_match || ' '` + `'(''%'' || '` + `'$1'` + `' || ''%'')'`
  - 즉 값 앞뒤에 `%`가 자동으로 붙는다(`NAME_VALUE ILIKE ('%' || $1 || '%')`). `=`일 때만 정확 일치. 사용자가 넣은 `%`/`_`는 LIKE 와일드카드로 그대로 작동한다. 따라서 `q=%.example.com`은 `%%.example.com%`와 같아져 "`.example.com`을 포함하는 모든 identity"가 되고, `example.com` 자체(점 없는 정확 일치)나 `foo.example.com.evil.com`처럼 뒤에 문자가 더 붙는 값도 매치될 수 있다. 정확한 서브도메인만 필요하면 클라이언트에서 접미사 검증이 필요하다.
- `%`만 있는 값 거부: fnc/web_apis.fnc:4617-4620 `IF trim(t_value, '%') = '' THEN RAISE no_data_found USING MESSAGE = ... 'Value not permitted: ''%'''`

### 2-3. exclude=expired (확인됨)
- fnc/web_apis.fnc:469-472 `t_temp := get_parameter('exclude', ...); IF lower(coalesce(',' || t_temp || ',', 'nothing')) LIKE ',expired,' THEN t_excludeExpired := '&exclude=expired';`
- 적용 조건: fnc/web_apis.fnc:4787-4790 `coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')` 및 `x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'`
- 값이 정확히 `expired`일 때만 인식된다(쉼표 구분 다중값은 `,expired,` LIKE 패턴이므로 `expired`가 단독일 때만 일치).

### 2-4. deduplicate=Y (확인됨)
- fnc/web_apis.fnc:474-476 `IF upper(coalesce(get_parameter('deduplicate', ...), 'N')) = 'Y' THEN t_deduplicate := TRUE;`  (대소문자 무관한 `Y`/`y`)
- 폼 문구: fnc/web_apis.fnc:969 `> Deduplicate (pre)certificate pairs?`

### 2-5. 그 외 파라미터 (확인됨)
- `excludecas`(콤마 구분 CA ID, fnc/web_apis.fnc:527), `group`(기본 none, :497), `sort`(:520), `dir`(:495/498), `showSQL`(:488), `minNotBefore`(:460; Identity 검색 쿼리에서는 사용되지 않고 lint류에서만 쓰임 - fnc/web_apis.fnc:4684-4686 `lci.NOT_BEFORE_DATE >= $2`).
- 페이지네이션 파라미터(`p`, `n`)는 issuer CA별 드릴다운(iCAID) HTML 경로에서만 보이며 JSON 도메인 검색에는 오프셋/페이지가 없다 (fnc/web_apis.fnc:4469 `IF t_pageNo IS NOT NULL` 은 그 경로에 한정; 이 부분은 읽은 범위 한정이라 JSON 전용 페이징 부재는 확인됨/미확인 혼합이므로 "발견하지 못함"으로 취급).

---

## 3. 제한 / 타임아웃 / 오류 동작

### 3-1. 결과 행 제한 (확인됨)
- fnc/web_apis.fnc:185 `c_resultLimit	CONSTANT	integer	:= 10000;`
- fnc/web_apis.fnc:4808-4810 `'                  LIMIT ' || c_resultLimit::text || chr(10) ||` `') sub'` (서브쿼리 안, 즉 `certificate_and_identities`의 "이름 행" 기준 10000행에서 자르며, ORDER BY 없이 LIMIT라 어떤 행이 남는지 보장 없음)
- 한계: 한도는 최종 인증서 수가 아니라 identity 행 수 기준이다. 인증서 1개가 SAN 여러 개를 가지면 일치한 행이 여러 개이므로 반환 인증서 수는 10000보다 적을 수 있다(코드 구조에서 도출).
- 잘림 안내는 HTML에만 있다: fnc/web_apis.fnc:5064 `IF (t_outputType = 'html') AND (t_count >= c_resultLimit) THEN` ... `<B>Sorry, your search results have been truncated.</B>` ... `only a random subset is shown below.` / `Please retry your search with <A ...>expired certificates excluded</A>.`
  -> JSON 출력에는 잘림 표시가 전혀 없다(확인됨). 반환 행 수가 큰 경우 `exclude=expired` 사용 권장은 코드의 안내문과 일치한다.
- t_count는 `RESULT_COUNT` 합계(:4905 부근 `t_count := t_count + l_record.RESULT_COUNT`)로, JSON 소비측에서 `result_count`로 잘림 여부를 추정하려면 합이 10000 이상인지 보는 방식이 코드 의도와 같다(추론; 확인 못 함).

### 3-2. 타임아웃 (확인 못 함)
- 저장소 전체에서 `statement_timeout`, `timeout`을 검색했으나 web_apis/스키마에서 질의 타임아웃 설정을 찾지 못했다(grep 결과 없음). 서버 측 타임아웃 값은 확인 못 함.

### 3-3. 오류 동작 (확인됨)
- fnc/web_apis.fnc:5659-5678: 예외 처리부.
  - `WHEN no_data_found THEN RETURN '[BEGIN_HEADERS] ... Content-Type: text/html; charset=UTF-8 [END_HEADERS] ' || coalesce(t_output, '') || '<BR><BR>' || SQLERRM || '</BODY></HTML>'`
  - `WHEN others THEN ... Content-Type: text/html; charset=UTF-8 ... html_escape(SQLERRM) ... html_escape(coalesce(t_query, ''))`
  - 즉 `output=json`이라도 오류가 나면 Content-Type이 `text/html`이며 본문은 HTML 조각(부분 JSON이 `t_output`에 이미 있었다면 그 앞부분 + HTML 오류 텍스트)이다. JSON 파서가 실패하므로 Go 클라이언트는 Content-Type 확인과 파싱 오류 처리가 필요하다.
- 지원 안 되는 output 값: fnc/web_apis.fnc:336-337 `RAISE no_data_found USING MESSAGE = 'Unsupported output type: ' || html_escape(t_outputType);`
- 검색 유형이 JSON을 지원하지 않으면 `t_isJSONOutputSupported`가 FALSE라서 위 :320 조건을 못 타고 `t_outputType NOT IN ('html','atom','csv')`면 위 오류, 아니면 계속 진행되어 `json`은 오류로 떨어진다(:336 분기; 확인됨).
- HTTP 상태 코드: 이 함수는 본문 문자열과 `[BEGIN_HEADERS]` 블록(Content-Type, Cache-Control 등)만 만들고 상태 코드를 지정하지 않는다. 실제 HTTP 응답을 만드는 웹 프런트엔드 코드는 이 저장소에 없다 -> HTTP 상태(예: 5xx, 429)는 확인 못 함.

### 3-4. 레이트 리밋 (확인 못 함)
- 저장소에 crt.sh 웹 질의에 대한 rate limit 코드/문서는 없다. 유일한 `REQUESTS_THROTTLE`은 sql/create_schema.sql:385 의 `ct_log` 테이블 열로, CT 로그 서버에 대한 crt.sh 자신의 수집 요청 스로틀 설정이며 웹 질의 제한과 무관하다(확인됨).
- 웹 프런트엔드 레벨 제한은 확인 못 함.

---

## 4. 이용약관 / 공정 사용(fair use) 문구

- README.md 전체: `# certwatch_db` / `Database schema` 뿐이다 (확인됨).
- fnc/web_apis.fnc 의 HTML 템플릿(검색 폼 등)과 저장소 전체에서 `terms`, `fair use`, `abuse`, `automated`, `rate`, `robots`, `scrap` 등을 검색한 결과, 자동 질의에 관한 이용 조건 문구는 없었다. 일치한 것은 GPL 라이선스 헤더("it under the terms of the GNU General Public License"), LICENSE 본문뿐이며 웹 서비스 이용약관과 무관하다.
- 라이선스 사실(확인됨): fnc/web_apis.fnc:1-3 `certwatch_db - Database schema / Written by Rob Stradling / Copyright (C) 2015-2026 Sectigo Limited`, GPLv3 이상. 이는 코드 라이선스이며 crt.sh 서비스 이용 조건이 아니다.
- 결론: 공식 소스 저장소에서 crt.sh 자동 질의 허용/금지에 대한 문구는 확인 못 함. (crt.sh 사이트 자체의 문구는 접근이 차단되어 있어 읽지 못했고, github.com/crtsh 조직의 다른 저장소 목록은 API 호출이 비어 있어 확인하지 못했다.) CLI에는 보수적인 요청 간격, User-Agent 명시, 결과 캐시를 두는 것을 권장하나 이는 코드 근거가 아닌 설계 판단이다.

---

## 5. 프리인증서/최종 인증서 중복과 deduplicate=Y

### 5-1. 기본 동작: 별도 행 (확인됨)
- 메인 쿼리는 `GROUP BY sub.CERTIFICATE` 로 인증서 바이트 단위로 묶는다: fnc/web_apis.fnc:4811 `'        GROUP BY sub.CERTIFICATE' || chr(10) ||`. 프리인증서와 최종 인증서는 DER 바이트가 다르므로(프리인증서에는 poison 확장이 있고 최종에는 SCT 확장이 있음) 서로 다른 그룹, 즉 서로 다른 행(`id`가 다름)이 된다.
- 프리인증서 표지 코드: fnc/web_apis.fnc:4964 부근(Atom 출력) `IF x509_print(t_certificate) LIKE '%CT Precertificate Poison%' THEN ... 'Precertificate'`. JSON 행에는 precert 여부를 나타내는 필드가 없다(SELECT 별칭 목록에 없음; 확인됨).
- 따라서 기본 JSON에는 같은 발급에 대한 (pre)cert 쌍이 중복되어 나올 수 있다. 이 사실은 "바이트가 다르다"는 코드 구조에서 도출한 것이며, 실제 응답 샘플에서 쌍을 확인한 것은 아니다.

### 5-2. deduplicate=Y (확인됨)
- fnc/web_apis.fnc:4762-4768:
  - `LEFT JOIN certificate c2 ON (`
  - `x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(cai.CERTIFICATE)`
  - `AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID`
  - `AND c2.ID < cai.CERTIFICATE_ID`
  - `AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(cai.CERTIFICATE)`
- fnc/web_apis.fnc:4805 `'                      AND c2.ID IS NULL'`
- 의미: 같은 serial, 같은 발급 CA, CT 관련 확장을 제거한 TBSCertificate가 같고, 더 작은 crt.sh ID의 인증서가 이미 존재하면 현재 행을 제외한다. 즉 (프리)인증서 쌍 중 ID가 가장 작은 하나만 남긴다. 폼 문구 `Deduplicate (pre)certificate pairs?` (fnc/web_apis.fnc:969)와 일치한다.
- 부수 효과: 중복 제거가 LIMIT 10000 이전(서브쿼리 WHERE 안)에서 적용되므로 한도 내에서 더 많은 고유 인증서를 얻는 데 유리하다(코드 순서에서 도출).
- 서브도메인 열거 목적이라면 `name_value`만 필요하므로 클라이언트에서 집합(set)으로 중복 제거하면 deduplicate 없이도 동일 결과를 얻는다(추론). 다만 서버측 LIMIT 소진을 줄이려면 `deduplicate=Y`가 유리하다.

---

## 구현 권고 요약 (코드 근거 있는 것만)
- 요청 (6절에서 고침: 파라미터 이름은 `dNSName`): `?dNSName=<domain>&match=ILIKE&exclude=expired&deduplicate=Y&output=json` 또는 `q=%25.<domain>`(%는 URL 인코딩 필요). dNSName 은 SAN dNSName으로 한정되어 노이즈가 적다(fnc/web_apis.fnc:428-429, 4798-4800).
- 응답 처리: 배열 -> 각 객체의 `name_value`를 `\n`으로 split -> 소문자화, 앞의 `*.` 제거, 도메인 접미사 검증, 집합 중복 제거.
- 응답 Content-Type이 application/json이 아니면 HTML 오류로 처리.
- 10000행 한도에 도달했을 가능성은 JSON에 신호가 없으므로 클라이언트가 `exclude=expired` 및 하위 도메인별 분할 질의로 대응.

---

## 6. 실제 응답으로 확인 (2026-11-04, 사용자가 `crt.sh` 접속을 허용한 뒤)

이 세션에서 crt.sh에 직접 요청해 확인했다. 아래는 모두 확인됨(실제 응답)이다.

- **파라미터 이름은 대소문자를 가린다.**
  - `?dNSName=github.com&match=ILIKE&deduplicate=Y&exclude=expired&output=json` → HTTP 200, `Content-Type: application/json`, 45행.
  - 같은 질의를 소문자 `dnsname=`으로 보내면 HTTP 404(Apache "Not Found" HTML)가 나왔고, 다시 보냈을 때는 HTTP 502가 나왔다.
  - `q=github.com…`과 `identity=github.com…`도 그 시각에 HTTP 502(`text/html`)였다. 일시 장애인지 파라미터 문제인지는 이것만으로 가를 수 없다.
  - 결론: 2-1절의 "소문자를 쓰는 것이 안전하다"는 추정은 틀렸다. **`dNSName`을 써야 한다.**
- **키 이름은 소문자다.** `common_name, id, issuer_ca_id, issuer_name, name_value, not_after, not_before, result_count, serial_number` (1-2절의 "확인 못 함"을 대체).
- **날짜 형식은 시간대 표시가 없는 `YYYY-MM-DDTHH:MM:SS`다.** 예: `"not_before": "2026-10-14T00:00:00"`, `"not_after": "2027-01-11T23:59:59"`. 시간대는 응답에 없다. 소스의 `now() AT TIME ZONE 'UTC'` 비교(2-3절)로 보아 UTC로 해석하는 것이 맞아 보이지만, 이는 추론이다.
- **`name_value`는 줄바꿈으로 구분된다.** 예: `"garage.github.com\ngist.github.com\ngithub.com\nwww.github.com"`. 와일드카드 이름(`*.`)도 실제로 들어 있었다 (1-3절의 "확인 못 함"을 대체).
- **`id`와 `result_count`는 JSON 숫자다.** 예: `29824981846`, `4`.
- **결과가 없으면 HTTP 200, `application/json`, 본문 `[]`다.** 없는 도메인으로 두 번 확인했다. 그 직전 한 번은 HTTP 502(`text/html`, nginx "502 Bad Gateway")가 나왔다.
- **crt.sh는 짧은 시간 안에도 502를 자주 돌려준다.** 재시도가 필요하다는 설계 판단(7.6절)과 맞다.
