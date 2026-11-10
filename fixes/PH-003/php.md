# PHP: prepared statement 쓰기

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
```

정렬 방향처럼 값으로 넘길 수 없는 부분은 허용 목록과 비교합니다.
