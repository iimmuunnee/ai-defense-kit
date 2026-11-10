<?php
// portone webhook
$sig = $_SERVER['HTTP_WEBHOOK_SIGNATURE'] ?? '';
$body = json_decode(file_get_contents('php://input'), true);
$payment = fetch('https://api.portone.io/payments/' . rawurlencode($body['data']['paymentId']));
