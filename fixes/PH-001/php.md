# PHP: 사용자 입력을 실행하지 않기

정해진 동작 중에서 고르게 합니다.

```php
$allowed = ['status' => 'git status', 'log' => 'git log -1'];
$command = $allowed[$userChoice] ?? null;
if ($command === null) {
    http_response_code(400);
    exit;
}
```

명령에 값을 꼭 넘겨야 하면 인자마다 `escapeshellarg()`를 씁니다.
