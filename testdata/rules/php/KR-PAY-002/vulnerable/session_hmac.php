<?php
// portone webhook: 세션 값에만 HMAC을 쓰고 웹훅 서명은 확인하지 않는다
$token = hash_hmac('sha256', session_id(), $key);
$body = json_decode(file_get_contents('php://input'), true);
mark_paid($body['data']['paymentId']);
