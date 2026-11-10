# PHP: 토스페이먼츠 웹훅 검증하기

다른 언어 안내와 같은 공식 절차(서명 검증, 결제 조회)를 PHP 7.3 이상용으로 옮긴 예시입니다. 공식 SDK 코드가 아니고, 실제 결제 환경이나 PHP 실행기로 돌려 보지는 않았습니다(확인 필요). `expected_amount`, `mark_order_paid`, `saved_secret`은 직접 만들어야 하는 예시 이름입니다.

```php
<?php
// 값이 없으면 멈춥니다. getenv()는 값이 없을 때 false를 돌려주는데, 그대로 쓰면
// 빈 키로 HMAC을 계산하게 되어 공격자도 같은 서명을 만들 수 있습니다.
function env_or_stop(string $name): string {
    $value = getenv($name);
    if ($value === false || $value === '') {
        http_response_code(500);
        exit;
    }
    return $value;
}

function signature_ok(string $raw): bool {
    $sentAt = $_SERVER['HTTP_TOSSPAYMENTS_WEBHOOK_TRANSMISSION_TIME'] ?? '';
    $header = $_SERVER['HTTP_TOSSPAYMENTS_WEBHOOK_SIGNATURE'] ?? '';
    $expected = hash_hmac('sha256', $raw . ':' . $sentAt, env_or_stop('TOSS_SECURITY_KEY'), true);
    foreach (explode(',', $header) as $part) { // 서명이 여러 개일 수 있습니다
        $part = trim($part);
        if (strpos($part, 'v1:') === 0) {
            $got = base64_decode(substr($part, 3), true);
            if ($got !== false && hash_equals($expected, $got)) {
                return true;
            }
        }
    }
    return false;
}

$raw = file_get_contents('php://input'); // JSON으로 바꾸기 전의 원문 그대로
if (!signature_ok($raw)) {
    http_response_code(401); // 실패하면 거부
    exit;
}
try {
    $body = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    http_response_code(400);
    exit;
}

if (($body['eventType'] ?? '') === 'PAYMENT_STATUS_CHANGED') {
    // 웹훅 본문이 아니라 결제 조회 결과로 대조합니다 (orderId, totalAmount, status 등)
    $paymentKey = (string) ($body['data']['paymentKey'] ?? '');
    $auth = base64_encode(env_or_stop('TOSS_SECRET_KEY') . ':');
    $ch = curl_init('https://api.tosspayments.com/v1/payments/' . rawurlencode($paymentKey));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Authorization: Basic ' . $auth],
    ]);
    $res = curl_exec($ch);
    if ($res === false || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 200) {
        http_response_code(502); // 조회에 실패하면 완료 처리하지 않습니다
        exit;
    }
    $payment = json_decode($res, true);
    if (($payment['status'] ?? '') === 'DONE'
        && ($payment['totalAmount'] ?? null) === expected_amount($payment['orderId'] ?? '')) {
        mark_order_paid($payment['orderId']);
    }
} elseif (isset($body['secret'], $body['orderId'])) {
    // 가상계좌 입금(DEPOSIT_CALLBACK): 본문에 eventType이 없습니다.
    // 결제 승인 응답으로 받아 저장해 둔 secret과 비교합니다.
    $saved = saved_secret($body['orderId']);
    if ($saved === null || !hash_equals($saved, (string) $body['secret'])) {
        http_response_code(401);
        exit;
    }
    if (($body['status'] ?? '') === 'DONE') {
        mark_order_paid($body['orderId']);
    }
}
```

`Authorization: Basic base64(시크릿 키 + ":")` 형식은 결제 승인 API에서 확인된 API 키 인증 방식이며, 결제 조회 API에도 같은 인증을 쓰는 것으로 보고 쓴 예시입니다(문서 원문 인용 아님, 확인 필요). `secret`을 `hash_equals`로 비교하는 것은 예시 권장이며 공식 문서의 요구는 아닙니다.
