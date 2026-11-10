<?php
// portone webhook: 세션 토큰만 비교하고 웹훅 서명은 확인하지 않는다
if (!hash_equals($_SESSION['token'], $token)) { exit; }
$body = json_decode(file_get_contents('php://input'), true);
mark_paid($body['data']['paymentId']);
