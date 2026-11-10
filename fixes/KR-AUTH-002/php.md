# PHP: 네이버 로그인에 state 붙이기

로그인을 시작할 때 무작위 값을 세션에 저장하고, 요청에 `state`로 함께 보냅니다.

```php
<?php
$clientId = getenv('NAVER_CLIENT_ID');
$redirectUri = getenv('NAVER_REDIRECT_URI');
if (empty($clientId) || empty($redirectUri)) {
    http_response_code(500); // 설정이 없으면 로그인을 시작하지 않습니다
    exit;
}
session_start();
$_SESSION['oauth_state'] = bin2hex(random_bytes(16));
$params = http_build_query([
    'response_type' => 'code',
    'client_id' => $clientId,
    'redirect_uri' => $redirectUri,
    'state' => $_SESSION['oauth_state'],
]);
header('Location: https://nid.naver.com/oauth2.0/authorize?' . $params);
```

```php
<?php
// 콜백에서 꼭 비교하세요
session_start();
$saved = $_SESSION['oauth_state'] ?? '';
unset($_SESSION['oauth_state']);
if ($saved === '' || !hash_equals($saved, $_GET['state'] ?? '')) {
    http_response_code(400);
    exit('잘못된 로그인 요청');
}
// 여기서부터 code로 토큰을 받는 단계를 진행
```
