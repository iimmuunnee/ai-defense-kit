<?php
// portone webhook
$sig = $_SERVER['HTTP_WEBHOOK_SIGNATURE'] ?? '';
$raw = file_get_contents('php://input');
$expected = base64_encode(hash_hmac('sha256', $signed, $key, true));
if (!hash_equals($expected, $sig)) { http_response_code(401); exit; }
