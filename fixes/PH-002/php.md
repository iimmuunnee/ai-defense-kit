# PHP: 허용한 파일만 불러오기

```php
$pages = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
$file = $pages[$userChoice] ?? 'pages/home.php';
include $file;
```
