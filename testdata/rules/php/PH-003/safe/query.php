<?php
// 값을 SQL 문과 분리한 예
$st = $pdo->prepare("SELECT * FROM u WHERE id = ?");
$st->execute([$_GET['id']]);
