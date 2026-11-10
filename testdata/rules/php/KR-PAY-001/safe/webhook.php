<?php
$raw = file_get_contents('php://input');
$sig = $_SERVER['HTTP_TOSSPAYMENTS_WEBHOOK_SIGNATURE'] ?? '';
check_signature($raw, $sig);
$body = json_decode($raw, true);
if ($body['eventType'] === 'PAYMENT_STATUS_CHANGED') {
    mark_paid($body['data']['orderId']);
}
