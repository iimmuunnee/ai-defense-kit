<?php
// portone webhook
$sig = $_SERVER['HTTP_WEBHOOK_SIGNATURE'] ?? '';
$body = json_decode(file_get_contents('php://input'), true);
mark_paid($body['data']['paymentId']);
