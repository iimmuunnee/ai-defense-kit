# PHP: 포트원 웹훅을 결제 재조회로 처리하기

이 문서를 쓸 때 포트원 웹훅 문서에는 PHP 서버 SDK가 나와 있지 않았습니다. 문서가 허용하는 방법대로, 웹훅 내용을 믿지 않고 결제 건을 API로 다시 조회합니다. 서명까지 직접 검증하려면 문서가 안내하는 Standard Webhooks 스펙을 따르세요. 실제 결제 환경에서 돌려 보지는 않았습니다.

```php
<?php
$apiSecret = getenv('PORTONE_API_SECRET');
if ($apiSecret === false || $apiSecret === '') {
    http_response_code(500); // 값이 없으면 조회할 수 없으므로 멈춥니다
    exit;
}
$body = json_decode(file_get_contents('php://input'), true);
$paymentId = $body['data']['paymentId'] ?? null;
if (!is_string($paymentId)) {
    exit; // 결제 건이 아닌 웹훅
}
$ch = curl_init('https://api.portone.io/payments/' . rawurlencode($paymentId));
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HTTPHEADER => ['Authorization: PortOne ' . $apiSecret],
]);
$res = curl_exec($ch);
if ($res === false || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 200) {
    http_response_code(502); // 조회에 실패하면 완료 처리하지 않습니다
    exit;
}
$payment = json_decode($res, true);
// 조회 결과의 상태와 금액을 주문과 대조한 뒤에만 완료 처리하세요.
```
