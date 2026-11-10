# 공식 자료 확인 기록: 웹 프레임워크, pip, osv-scalibr (2026-11-04)

문서 사이트(fastapi.tiangolo.com, starlette.io, nextjs.org, pip.pypa.io)는 이 환경에서 막혀 있어, 각 프로젝트의 공식 GitHub 저장소 원문(raw.githubusercontent.com)과 로컬 Go 모듈 캐시의 소스를 읽었다. VERIFIED는 공식 원문을 직접 읽은 것, UNVERIFIED는 확인하지 못한 것이다.

- osv-scalibr 연결: 이 저장소의 go.mod가 `github.com/google/osv-scalibr v0.5.4-0.20261009010329-5be78a00e3c2`를 고정하고 있어, 아래 Q5에서 읽은 버전과 같다 (VERIFIED, go.mod 97행).


## Q1 FastAPI 문서 페이지 노출
- 확인됨(VERIFIED) fastapi/fastapi/master/docs/en/docs/tutorial/metadata.md L105: "If you want to disable the OpenAPI schema completely you can set `openapi_url=None`, that will also disable the documentation user interfaces that use it." (뜻: OpenAPI 스키마를 완전히 끄려면 `openapi_url=None`으로 설정하면 되고, 이는 그것을 쓰는 문서 화면도 함께 끈다.)
- 확인됨(VERIFIED) 같은 파일 L112-116: "You can disable it by setting `docs_url=None`." / "You can disable it by setting `redoc_url=None`."
- 확인됨(VERIFIED) fastapi/fastapi/master/docs/en/docs/how-to/conditional-openapi.md:
  - `/openapi.json`, `/docs`, `/redoc`에 접속하면 "you will just get a `404 Not Found` error"가 나온다.
  - 기본 `openapi_url`은 "/openapi.json"이다 ("the same default of `"/openapi.json"`").
- 확인됨(VERIFIED) FastAPI는 문서 화면을 끄라고 권장하지 않는다. 문서의 문장: "Hiding your documentation user interfaces in production *shouldn't* be the way to protect your API." ... "It could be considered simply a form of [Security through obscurity]". 또한: "you might have a very specific use case where you really need to disable the API docs for some environment (e.g. for production)". 이 문서는 환경변수로 OpenAPI를 조건부로 켜고 끄는 방법을 선택 사항으로 안내한다.
  - (뜻: 운영 환경에서 문서 화면을 숨기는 것이 API를 보호하는 방법이 되어서는 안 된다. 단순히 "모호함에 의한 보안"의 한 형태로 볼 수 있다. 특정 환경(예: 운영)에서 API 문서를 꼭 꺼야 하는 아주 특수한 경우가 있을 수는 있다.)
  => 규칙 심각도: 참고용/낮음(informational/low)이며, 취약점은 아니다.

## Q2 CORS
- 확인됨(VERIFIED) fastapi/.../docs/en/docs/tutorial/cors.md L27-31: "It's also possible to declare the list as `"*"` (a "wildcard") to say that all are allowed. But that will only allow certain types of communication, excluding everything that involves credentials: Cookies, Authorization headers like those used with Bearer Tokens, etc." (뜻: 목록을 `"*"`(와일드카드)로 선언해 모두 허용할 수도 있지만, 쿠키나 Bearer 토큰 같은 Authorization 헤더 등 자격 증명이 걸린 통신은 제외된다.)
- 확인됨(VERIFIED) 같은 파일 L62: "None of `allow_origins`, `allow_methods` and `allow_headers` can be set to `['*']` if `allow_credentials` is set to `True`. All of them must be explicitly specified."
- 확인됨(VERIFIED) encode/starlette/master/docs/middleware.md L169: "`allow_credentials` - Indicate that cookies should be supported for cross-origin requests. Defaults to `False`. Also, `allow_origins`, `allow_methods` and `allow_headers` cannot be set to `['*']` for credentials to be allowed, all of them must be explicitly specified."
- 확인됨(VERIFIED) encode/starlette/master/starlette/middleware/cors.py (코드는 문서 내용을 강제하지 않고 Origin을 그대로 되돌려 준다):
  - L35 `allow_all_origins = "*" in allow_origins`; L94-95 `is_allowed_origin`: `if self.allow_all_origins: return True` (어떤 Origin이든 허용).
  - L37 `preflight_explicit_allow_origin = not allow_all_origins or allow_credentials`; L111-115 preflight: 허용되고 위 플래그가 true이면 `headers["Access-Control-Allow-Origin"] = requested_origin` (요청 Origin을 그대로 반사). L42-43/61-62는 `Access-Control-Allow-Credentials: true`를 추가한다.
  - 단순/실제 요청 L162-164: "# If credentials are allowed, then we must respond with the specific origin instead of '*'." `if origin is not None and self.allow_all_origins and self.allow_credentials: self.allow_explicit_origin(headers, origin)` -> L175-177에서 ACAO = 요청 Origin으로 설정하고 Vary: Origin을 추가한다.
  - 결론: allow_origins=["*"] + allow_credentials=True이면 Starlette는 어떤 요청 Origin이든 ACAO=<origin>, ACAC=true로 되돌려 준다 => 어느 사이트에서든 자격 증명이 포함된 교차 출처 읽기가 허용된다(문서가 암시하는 것보다 더 나쁘다). 생성 시점에 예외나 경고는 나오지 않는다. (참고: master 기준으로 읽은 것이며, 설치된 버전은 확인하지 않았다.)

## Q3 Next.js CVE-2025-29927
- 확인됨(VERIFIED) github/advisory-database/main/advisories/github-reviewed/2025/03/GHSA-f82v-jwr5-mffw/GHSA-f82v-jwr5-mffw.json (경로 실재, HTTP 200). id GHSA-f82v-jwr5-mffw, alias CVE-2025-29927, summary "Authorization Bypass in Next.js Middleware".
- 영향받는 버전 (npm `next`, ECOSYSTEM 범위): 12.0.0 도입 12.3.5 수정; 13.0.0 수정 13.5.9; 14.0.0 수정 14.2.25; 15.0.0 수정 15.2.3. (즉 >=12.0.0 <12.3.5, >=13.0.0 <13.5.9, >=14.0.0 <14.2.25, >=15.0.0 <15.2.3). 권고문 본문에 11.x도 언급된다: "For Next.js 11.x, consult the below workaround." (11.x는 영향 범위 목록에는 없음.)
- 심각도: CVSS_V3 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" (CVSS 계산으로는 7.5이나 파일에 명시되어 있지 않다 - 계산한 값이므로 확인 못 함(UNVERIFIED)으로 취급); database_specific.severity "CRITICAL"; cwe_ids CWE-285, CWE-863. (벡터와 등급이 서로 맞지 않는 것은 파일에 게시된 그대로다.)
- 인용: "It is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware." (뜻: 인가 검사가 미들웨어에서 이루어진다면 Next.js 애플리케이션의 인가 검사를 우회할 수 있다.)
- 헤더: "we recommend that you prevent external user requests which contain the `x-middleware-subrequest` header from reaching your Next.js application." 또한 "Next.js deployments hosted on Vercel are automatically protected against this vulnerability."
- 확인됨(VERIFIED) vercel/next.js/canary/docs/01-app/02-guides/authentication.mdx L1120 (미들웨어가 지금은 "Proxy"로 불린다): "While Proxy can be useful for initial checks, it should not be your only line of defense in protecting your data. The majority of security checks should be performed as close as possible to your data source, see [Data Access Layer](#creating-a-data-access-layer-dal) for more information."
  - L1016: "Optimistic: ... session data stored in the cookie" 대 "Secure: ... session data stored in the database".
  - L1463: "A common pattern in SPAs is to `return null` ... This pattern is **not recommended**".
  - 주의: 이 문구는 canary(Proxy로 이름이 바뀐 버전) 기준이다. 예전 문서는 "Middleware"라고 썼으며, 그쪽은 읽지 않았다.

## Q4 pip requirements 형식
- 확인됨(VERIFIED) pypa/pip/main/docs/html/reference/requirements-file-format.md "Structure": "- `[[--option]...]` - `<requirement specifier>` - `<archive url/path>` - `[-e] <local project path>` - `[-e] <vcs project url>`".
- 같은 파일의 예시 블록:
  - "pytest" (이름만, 버전 지정 없음); "docopt == 0.6.1"
  - "requests [security] >= 2.8.1, == 2.8.* ; python_version < "2.7""
  - "urllib3 @ https://github.com/urllib3/urllib3/archive/refs/tags/1.26.8.zip"
  - "-r other-requirements.txt"; "-c constraints.txt"; "./downloads/numpy-1.9.2-cp34-none-win32.whl"; wheel을 가리키는 맨 http URL
  - 요구사항별 옵션: "`--hash` (for Hash-checking mode)"와 `--config-settings`.
- 확인됨(VERIFIED) pypa/pip/main/docs/html/reference/requirement-specifiers.md: "SomeProject == 1.3", "SomeProject >= 1.2, < 2.0", "SomeProject ~= 1.4.2", "SomeProject == 5.4 ; python_version < '3.8'", "SomeProject ; sys_platform == 'win32'".
- 확인됨(VERIFIED) python/peps/main/peps/pep-0440.rst: "* ``==``: Version matching clause", "* ``===``: Arbitrary equality clause."; "Arbitrary equality comparisons are simple string equality operations ... This operator also does not support prefix matching as the ``==`` operator does." 또한 `==`는 접두사 와일드카드(`== 2.8.*`, 위 예시)를 허용하는데, 이것은 정확한 고정(pin)이 아니다.
- 확인됨(VERIFIED) pypa/pip/main/docs/html/topics/secure-installs.md (해시 검사 모드): "Requirements must be pinned (either to a URL, filesystem path or using `==`)."
- 정확한 고정 형태: `==X.Y.Z` (`*` 없음), `===X`. 정확한 고정이 아닌 것: 버전 지정 없음, `>=`, `~=`, `<`, `!=`, `,`로 이은 범위, `== X.*`. URL/경로/-e/-r은 버전이 아니다.

## Q5 osv-scalibr (캐시에 있는 모듈: github.com/google/osv-scalibr@v0.5.4-0.20261009010329-5be78a00e3c2; osv-scanner v2@v2.7.0이 /root/go/pkg/mod/github.com/google/osv-scanner/v2@v2.7.0 에 있으며, internal/scalibrplugin/presets.go:40 과 pkg/osvscanner/internal/scanners/lockfile.go:35 에서 python/requirements를 import한다. v2.7.0의 go.mod가 정확히 이 scalibr 버전을 고정하는지는 확인하지 않았다 -> 연결 관계는 확인 못 함(UNVERIFIED))
디렉터리: .../osv-scalibr@v0.5.4-0.20261009010329-5be78a00e3c2/extractor/filesystem/language/python/requirements/requirements.go
- 확인됨(VERIFIED) L49-56: "// We currently don't handle the following constraints. // * Version wildcards (*) // * Less than (<) // * Not equal to (!=) // * Multiple constraints (,)" `reUnsupportedConstraints = regexp.MustCompile(`\*|<[^=]|,|!=`)`
- L~226 `l = ignorePythonSpecifier(l)` (환경 마커 제거: `strings.SplitN(s, ";", 2)[0]`); `l = removeExtras(l)`; `--hash` 옵션은 분리되어 Metadata.HashCheckingModeValues로 들어간다.
- `-r path`는 따라간다(extraPaths에 추가). "-"로 시작하는 다른 줄(-e, -c 포함)은 건너뛴다("Global options other than -r are not implemented.").
- getLowestVersion (L320-):
  - 지원하지 않는 제약 => `// Return the name so the package will be in the list for dependency resolution. return nameFromRequirement(s), "", ""` -> 패키지는 보고되지만 버전은 비어 있다.
  - 구분자 `"===", "==", ">=", "<=", "~="`: 구분자 뒤의 텍스트가 버전이 되고 비교 연산자(comparator)가 기록된다. `>=1.2`는 Version "1.2"와 Metadata.VersionComparator ">="를 낳는다(최저 버전으로 취급되며, 해석(resolve)되지도 건너뛰어지지도 않는다). 참고: 검사 순서는 "===" 먼저, 그다음 "==", ">=", "<=", "~=".
  - 구분자 없음(이름만): `// Length of t being 0 indicates that there is no separator. return strings.TrimSpace(s), "", ""` -> 버전이 빈 채로 보고된다.
- L245-262: `name, version, comp := getLowestVersion(l); if name == "" {continue}; if version == "" && comp != "" { continue }` (비교 연산자는 있는데 버전이 없을 때만 건너뜀) 이후 `pkgs = append(... Version: version, ... VersionComparator: comp, Requirement: requirement)`.
- 결과:
  - 고정되지 않은 것(버전 지정 없음 / 와일드카드 / 범위 / != / <) => 패키지는 Version ""로 내보내진다(건너뛰지 않으며, 여기서 해석되지도 않는다. "for dependency resolution" 주석은 이후의 해석기/guided-remediation 단계가 값을 채울 수 있음을 시사하지만, 이 디렉터리에서는 확인하지 않았다).
  - `>=`, `<=`, `~=` => 명시된 버전을 최저 버전인 것처럼 하여 내보낸다.
  - URL/`name @ url` 줄: 구분자가 없으므로 이름이 "name @ url"이 되어 isValidPackage(reValidPkg)를 통과하지 못해 건너뛰어진다(코드로부터 추론한 것이며 실행해 보지는 않았다). 맨 URL/경로도 마찬가지로 isValidPackage를 통과하지 못해 건너뛰어진다.
- 확인 못 함(UNVERIFIED): osv-scanner v2.7.0이 매칭 시점에 Version==""을 어떻게 다루는지(읽지 않음).
