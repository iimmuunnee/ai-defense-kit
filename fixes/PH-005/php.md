# PHP: 저장 이름을 서버에서 만들기

```php
$allowed = ['image/jpeg' => 'jpg', 'image/png' => 'png'];
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmpPath); // 사용자가 보낸 type을 믿지 않습니다
if (!isset($allowed[$mime])) {
    http_response_code(400);
    exit;
}
move_uploaded_file($tmpPath, 'uploads/' . bin2hex(random_bytes(16)) . '.' . $allowed[$mime]);
```

업로드 폴더에서 PHP가 실행되지 않도록 웹 서버도 설정하세요.
