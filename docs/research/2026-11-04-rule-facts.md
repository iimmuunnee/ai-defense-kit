# 규칙 근거 자료 (벤더 소유 GitHub 저장소 + npm 레지스트리)

공식 문서 사이트(docs.tosspayments.com, developers.kakao.com, developers.naver.com, supabase.com, developers.portone.io)에는 접속할 수 없었다(ENOTFOUND). 아래 사실은 벤더가 소유한 저장소와 npm에서만 가져왔다.
저장소 복제본은 .../scratchpad/clones/ 아래에 있다(supa = supabase/supabase의 apps/docs/content/guides만 부분 체크아웃, portone = portone-io/developers.portone.io 부분 체크아웃, tosspayments_*, naver_*, kakao_*). 읽기만 했고 아무것도 실행하지 않았다.
아래 저장소 경로는 위 복제본 기준 상대 경로다. Supabase 문서 경로 = supabase/supabase@master apps/docs/content/guides/...

## Q1 토스페이먼츠 웹훅
접속 가능한 공식 저장소는 github.com/tosspayments 아래의 browser-sdk, tosspayments-sample, payment-widget-sample이다. 공식 문서 저장소와 공식 서버 SDK는 찾지 못했다(tosspayments-docs, docs, server-sdk, webhook-sample 등을 시도했지만 없거나 비공개). 토스 GitHub 검색은 할 수 없었다(gh api search/orgs 차단).
- 결제 웹훅의 서명 헤더 / HMAC: 확인 못 함(UNVERIFIED). 공식 토스 저장소 어디에서도 찾지 못했다(tosspayments-sample, payment-widget-sample, browser-sdk에서 webhook|HMAC|createHmac|signature를 grep했으나 검증 코드가 나오지 않았다). `tosspayments-webhook-signature`, PAYMENT_STATUS_CHANGED, 정산(payout) 서명, HMAC 키/메시지: 확인 못 함(공식 페이지를 읽지 못함).
  - 제3자 GitHub 코드 검색에서 `tosspayments-webhook-signature`가 나오는 결과가 있다(예: jlinsights/FamilyOffice lib/payments/toss-webhook-signature.ts, ganji-saju/ganji-saju src/lib/payments/webhook-signature.ts). 하지만 공식이 아니며, 많아야 이 헤더 이름이 존재한다는 힌트 정도다.
- 가상계좌 콜백이 본문의 `secret` 필드를 쓴다: 확인됨(VERIFIED, 공식 샘플의 형태만). 출처: tosspayments/tosspayments-sample php-javascript/virtual_account_webhook.php (asp-javascript/public/payment/virtual_account_webhook.asp, jsp-javascript/public/payment/virtual_account_webhook.jsp 도 같음). 인용: `$secret = $json->secret; $status = $json->status; $orderId = $json->orderId;`.
  - 이 샘플은 값을 그대로 출력(echo)할 뿐, secret을 저장된 값과 비교하지 않는다.
  - secret을 결제 객체의 값과 비교해야 한다는 점: 확인 못 함(UNVERIFIED, 문서를 읽지 못함).
- 결제 승인(Confirm) API: 확인됨(VERIFIED). 경로 `POST https://api.tosspayments.com/v1/payments/confirm`, 인증은 시크릿 키 + ":"를 쓴 HTTP Basic. 출처: tosspayments/payment-widget-sample payment/payment-easypay-window/node/routes/index.js:15 ; tosspayments-sample express-javascript/server.js:17 `"Basic " + Buffer.from(apiSecretKey + ":").toString("base64")`.
- `GET /v1/payments/{paymentKey}` 조회와, 토스가 다시 조회하라고 권장하는지 여부: 확인 못 함(UNVERIFIED, 읽은 공식 파일에 없음).
- 토스 브라우저 SDK npm 패키지: registry.npmjs.org로 확인됨(VERIFIED) (repository -> github.com/tosspayments/browser-sdk): `@tosspayments/tosspayments-sdk` 2.10.0, `@tosspayments/payment-sdk` 1.9.3, `@tosspayments/payment-widget-sdk` 0.12.2, `@tosspayments/sdk` 1.3.1 (스크립트 로더; repo 필드 없음). 프론트엔드 결제 코드와 서버 코드를 구분하는 데 쓸 수 있다.
- 공식 샘플에 들어 있는 샘플 시크릿 키 문자열(테스트 키, 공개): express-javascript/server.js:10-11의 `test_gsk_docs_...`, `test_sk_...`.

## Q2 카카오 로그인
출처: kakao/kakao-ios-sdk (공식), Sources/KakaoSDKCommon/common/common/Urls.swift
- 호스트 `kauth: String = "kauth.kakao.com"` (38행); 경로 `authAuthorize = "/oauth/authorize"`, `authToken = "/oauth/token"` (122, 124행): 확인됨(VERIFIED). 즉 https://kauth.kakao.com/oauth/authorize 와 https://kauth.kakao.com/oauth/token 이다. 다만 스킴(scheme) 조립 부분은 읽지 않았으므로 https라는 가정은 확인 못 함(UNVERIFIED).
- authorize의 `state` 지원과 카카오의 CSRF 권장 사항: 확인 못 함(UNVERIFIED). iOS SDK는 URL+Utils.swift:45에서 `state` 쿼리 파라미터를 파싱할 뿐이다(`let state = parameters["state"]`). 권장 문구는 없다. developers.kakao.com은 읽을 수 없었다.

## Q3 네이버 로그인
출처: naver/naveridlogin-sdk-android (공식), Nid-OAuth/src/main/java/com/navercorp/nid/...
- authorize URL: 확인됨(VERIFIED). activity/NidOAuthQuery.kt:31 `REQUEST_AUTHORIZE_URL = "https://nid.naver.com/oauth2.0/authorize?"`.
- authorize 요청에 state를 보냄: SDK 동작으로 확인됨(VERIFIED). NidOAuthQuery.kt:80 `"state" to getOAuthInfo.getOAuthState()`가 `"response_type" to "code"`와 함께 있다.
- 토큰 엔드포인트: 확인됨(VERIFIED). NidServiceLocator.kt:31 `NID_OAUTH_BASE_URL = "https://nid.naver.com/oauth2.0/"` + data/service/NidOAuthLoginService.kt `@GET("token")` => https://nid.naver.com/oauth2.0/token (GET).
  - 파라미터에 `client_id`, `client_secret`, `grant_type=authorization_code`, `state`, `code`가 들어간다. 즉 state는 토큰 엔드포인트에도 전달된다(확인됨, SDK 코드).
- "state는 필수"와 "콜백에서 반드시 검증해야 한다"가 공식 문서의 문장인지: 확인 못 함(UNVERIFIED, 문서를 읽을 수 없음). SDK의 NidOAuthBridgeActivity.kt:322에 `// TODO code 넣을때 state체크 처리해야 함.`이라는 주석(state 확인에 관한 TODO)이 있지만, 이는 문서화된 규칙이 아니다.

## Q4 Supabase (출처: supabase/supabase@master apps/docs/content/guides, 그리고 raw URL https://raw.githubusercontent.com/supabase/supabase/master/apps/docs/content/guides/database/postgres/row-level-security.mdx = 200)
(a) RLS
- 활성화: 확인됨(VERIFIED). database/postgres/row-level-security.mdx:129 `alter table public.reports enable row level security;`
- 경고: 확인됨(VERIFIED). 같은 파일:12 "A table in an exposed schema without RLS is readable and writable by any role with a grant on it. Enable RLS on every table in an exposed schema." (뜻: RLS가 없는 노출된 스키마의 테이블은 권한(grant)이 있는 어떤 역할이든 읽고 쓸 수 있다. 노출된 스키마의 모든 테이블에 RLS를 켜라.)
- api/securing-your-api.mdx:252 확인됨(VERIFIED): "Tables and views exposed through the Data API without RLS can be accessed by any role with matching grants."
- 기본 권한(grant): 확인됨(VERIFIED).
  - securing-your-api.mdx:33 "On existing projects, new objects in `public` receive the following default privileges"
  - row-level-security.mdx:60 "a new table in `public` starts with every privilege already granted to all three roles"
  - securing-your-api.mdx:48 "Supabase is changing the platform default to revoke these automatic grants so that exposure becomes opt-in."
- SQL 마이그레이션으로 만든 테이블은 기본적으로 RLS가 꺼져 있는가? 문서에 이렇게 명시한 문장은 없다. 암시되는 내용: 새 테이블은 `enable row level security`를 실행하기 전까지 RLS가 켜지지 않는다.
  - 근거: 문서의 "Follow these steps for every table in an exposed schema"; row-level-security.mdx:122는 grant와 RLS를 같은 마이그레이션에 넣으라고 권고; securing-your-api.mdx:182 "Bundle grants with your RLS setup in the same migration".
  - "SQL로 만든 테이블은 기본적으로 RLS가 꺼져 있다"는 명시적 문장: 이 파일들에서는 확인 못 함(UNVERIFIED) (대시보드 테이블 에디터의 기본값은 읽지 않았다).
  - RLS를 자동으로 켜 주는 이벤트 트리거가 있다: row-level-security.mdx:244 -> /docs/guides/database/postgres/event-triggers.
(b) 키 (getting-started/api-keys.mdx)
- 형식 확인됨(VERIFIED) (50-53행):
  - publishable `sb_publishable_...` (낮은 권한, "Safe to expose online")
  - secret `sb_secret_...` ("Only use in backend components")
  - 레거시 `anon`과 `service_role` = "JWT (long-lived)", "Legacy version of publishable keys / secret keys"
  - 55행: "Publishable and secret keys are short strings, not JWTs ... a long key that begins with `eyJ`, it was written for the legacy keys."
- 브라우저에 절대 넣지 말 것, 확인됨(VERIFIED):
  - api-keys.mdx:103 "A secret key bypasses every Row Level Security policy you have. Never put one in a browser, a shipped application, or source control."
  - auth/users.mdx:113 "The secret key (`sb_secret_...`, which replaces the legacy `service_role` key) bypasses Row Level Security and must only be used in a secure server environment. Never expose it in a browser or any publicly accessible client."
  - realtime/postgres-changes.mdx:3468 "Do not expose the `service_role` token on the client"
  - row-level-security.mdx:66 service_role은 "bypasses RLS, so keep it server-side"
  - 시크릿 키를 브라우저에서 쓰면 HTTP 401이 돌아온다(api-keys.mdx:113).
- 환경변수 이름 확인됨(VERIFIED), api-keys.mdx:121-127: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_...`, 서버 전용 `SUPABASE_SECRET_KEY=sb_secret_...` ("Never prefix these, or your bundler will ship the key").
  - 문서에 나오는 그 밖의 이름: `SUPABASE_SECRET_KEY` (ai/langchain.mdx:85), `SUPABASE_SERVICE_ROLE_KEY`와 `SUPABASE_ANON_KEY` (Edge Function 환경변수, getting-started/migrating-to-new-api-keys.mdx:109,119; 레거시), `NEXT_PUBLIC_SUPABASE_ANON_KEY` (integrations/vercel-preview-branches.mdx, local-development/running-multiple-local-projects.mdx; 레거시).
  - Edge Function에는 `SUPABASE_PUBLISHABLE_KEYS` / `SUPABASE_SECRET_KEYS`(JSON 객체)도 제공된다.

## Q5 PortOne V2
- 브라우저 SDK 패키지: https://registry.npmjs.org/@portone/browser-sdk (200)로 확인됨(VERIFIED): 이름 `@portone/browser-sdk`, 최신 0.1.13, 설명 "PortOne SDK for browser".
  - 레지스트리에 repository 필드가 없다. npm이 벤더의 패키지 레지스트리이긴 하지만 소유권은 독립적으로 확인하지 못했다: 소유권은 확인 못 함(UNVERIFIED).
  - 내가 읽은 portone-io/developers.portone.io 부분 체크아웃에는 이 패키지를 이름으로 언급하는 mdx가 없었다.
- 서버 SDK: 레지스트리로 확인됨(VERIFIED): `@portone/server-sdk` 0.19.0, repository github.com/portone-io/server-sdk (directory javascript).
- 웹훅 검증(덤, 확인됨(VERIFIED)): portone-io/developers.portone.io src/routes/(root)/opi/ko/integration/webhook/readme-v2.mdx.
  - 인용: "포트원은 Standard Webhooks에 따른 메시지 검증을 지원합니다"; "웹훅 메시지를 신뢰하지 않고, 결제 건의 상태를 포트원 API를 통해 새로 조회하여 이 응답만 신뢰하기"
  - 코드: `PortOne.Webhook.verify(process.env.PORTONE_WEBHOOK_SECRET, ...)`, `PortOne.PortOneClient(process.env.PORTONE_API_SECRET)`, `PortOne.Errors.WebhookVerificationError`
  - 시크릿은 "환경 변수로 관리하시는 것을 권장"
  - Standard Webhooks 헤더(webhook-id, webhook-timestamp, webhook-signature)는 링크된 표준 명세에서 나온 것이며 그 명세는 읽지 않았다: 확인 못 함(UNVERIFIED).

## Q1 (재확인, 2026-11-04): 토스페이먼츠 공식 문서 직접 확인

사용자가 이 세션의 네트워크 설정에서 `docs.tosspayments.com`을 허용한 뒤, 공식 개발자센터 문서(Markdown 원문, `.md`)를 직접 읽었다. 아래는 모두 VERIFIED(공식 문서 원문)이다. 위 Q1의 UNVERIFIED 항목은 이 절로 대체한다.

- **웹훅 서명 헤더**: https://docs.tosspayments.com/reference/using-api/webhook-events.md
  - "`tosspayments-webhook-signature` 웹훅 서명입니다. 토스페이먼츠가 보낸 웹훅인지 검증할 수 있는 값입니다."
  - 검증 방법: "`{WEBHOOK_PAYLOAD}:{tosspayments-webhook-transmission-time}` 값을 [보안 키](/guides/v2/payouts#보안-키)로 HMAC SHA-256 해싱하세요." / "웹훅 헤더에서 `v1:` 뒤에 오는 값을 각각 base64로 디코딩하세요. `,` 구분자로 2개 이상의 서명이 포함될 수 있으므로…" / 하나라도 일치하면 올바른 웹훅.
  - 다른 헤더: `tosspayments-webhook-transmission-time`, `tosspayments-webhook-transmission-retried-count`, `tosspayments-webhook-transmission-id`.
- **보안 키**: https://docs.tosspayments.com/guides/v2/payouts.md "보안 키" 절. 개발자센터 API 키 메뉴의 "API 개별 키 > 보안 키", "64자의 Hexadecimal 문자열", "절대 외부에 노출되면 안 됩니다".
- **모든 웹훅에 서명이 있음 + 결제 웹훅은 재조회**: https://docs.tosspayments.com/guides/v2/get-started/llms-quick-reference.md §7.2 "Every webhook event includes the `tosspayments-webhook-signature` header. Verify it with HMAC SHA-256 using the security key. For payment webhooks, also re-call Payment Query API with `paymentKey` to verify status."
- **결제 조회 API 경로**: 같은 문서 "**Query**: `GET /v1/payments/{paymentKey}` or `GET /v1/payments/orders/{orderId}`".
- **공식 보안 체크리스트**: https://docs.tosspayments.com/reference/using-api/security-checklist.md "4. 웹훅 서명을 검증하고, 콜백을 https로 받아요"
  - "웹훅은 외부에서 상점 서버로 들어오는 요청이에요. 검증 없이 처리하면 위조된 결제 완료 통보로 상품이 나갈 수 있어요."
  - "`tosspayments-webhook-signature`를 검증해서 토스페이먼츠가 보낸 웹훅인지 확인한 뒤에만 처리한다", "서명 검증에 실패하면 요청을 거부한다 (로그만 남기고 처리하면 안 돼요)"
  - "웹훅 본문의 금액·주문번호를 그대로 사용하지 않고, 결제 조회 API로 교차 확인한다. 이때 `orderId`·`totalAmount`와 함께 `mId`, `status`도 같이 대조한다"
  - "서명은 토스페이먼츠가 보낸 웹훅이 맞는지만 보장해요. 금액과 상태는 결제 조회 API 교차 확인이 기본 방어선이에요."
- **이벤트 타입**: webhook-events.md, guides/v2/webhook.md: `PAYMENT_STATUS_CHANGED`(카드·계좌이체·휴대폰·상품권 결제 상태), `DEPOSIT_CALLBACK`(가상계좌 입금), `CANCEL_STATUS_CHANGED` 등. 본문 필드 `eventType`, `createdAt`, `data`(Payment 객체).
- **가상계좌 `secret`**: webhook-events.md DEPOSIT_CALLBACK "secret: 가상계좌 웹훅 요청이 정상적인 요청인지 검증하는 값입니다. 결제 승인 API의 응답으로 돌아온 `secret`과 같으면 정상적인 요청입니다." / https://docs.tosspayments.com/guides/v2/payment-window/integration-virtual-account.md "이벤트 본문의 `secret` 값이 결제 승인 응답으로 돌아온 Payment 객체의 `secret` 값과 같은지 확인하세요." "이후에 결제 조회를 할 때는 보안 이유로 `secret` 값이 `null`로 돌아옵니다."
- **비밀 키 형식과 노출 금지**: llms-quick-reference.md §2.1 "Secret key | `(test|live)_sk_*` | Server", "Never put the secret key in `NEXT_PUBLIC_*` (Next.js), `VITE_*` …"

## Q1 실험 (2026-11-04): 테스트 상점에서 실제 웹훅으로 서명 방식 확인

공식 문서에 없는 "보안 키를 어떤 바이트로 쓰는가"를 사용자의 토스페이먼츠 **테스트 상점**에서 직접 확인했다.

- 방법: 테스트 시크릿 키로 `POST /v1/virtual-accounts`(1,000원, 은행 코드 20)로 가상계좌를 발급 → 개발자센터 웹훅 메뉴에 수집용 URL(webhook.site)을 `DEPOSIT_CALLBACK`, `PAYMENT_STATUS_CHANGED`로 등록 → 테스트 거래내역에서 "입금처리" → 도착한 웹훅 2건의 원문 본문과 헤더로 `tools/toss-webhook-check`의 계산을 돌림.
- 결과 (VERIFIED, 실험):
  - 두 웹훅 모두 `tosspayments-webhook-signature`(서명 1개)와 `tosspayments-webhook-transmission-time` 헤더가 있었다. `DEPOSIT_CALLBACK`에도 서명이 붙는다.
  - `HMAC-SHA256("{원문 본문}:{transmission-time}", 보안 키)`에서 보안 키(64자 16진수 문자열)를 **문자열 그대로(UTF-8 바이트)** 쓰면 두 건 모두 일치, **16진수로 디코딩**하면 두 건 모두 불일치.
  - `DEPOSIT_CALLBACK` 본문의 `secret`은 가상계좌 발급(승인) 응답의 `secret`과 같았다.
  - `DEPOSIT_CALLBACK` 본문 키는 `createdAt, orderId, secret, status, transactionKey`뿐이고 **`eventType` 필드가 없다.** `PAYMENT_STATUS_CHANGED` 본문은 `createdAt, data, eventType`.
- 한계: 테스트 상점 1곳, 웹훅 2건으로 확인한 결과다. 라이브 환경이나 다른 이벤트에서 다를 가능성은 확인하지 않았다.
- 규칙에 주는 영향: `DEPOSIT_CALLBACK` 본문에 `eventType`이 없으므로, 가상계좌 웹훅 처리 코드는 `"DEPOSIT_CALLBACK"` 문자열을 쓰지 않을 수 있다. KR-PAY-001의 `has_any`가 이런 코드를 놓칠 수 있다 (남은 과제로 기록).
