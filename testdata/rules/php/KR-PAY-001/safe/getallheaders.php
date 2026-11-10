<?php
$headers = getallheaders();
check_signature(file_get_contents('php://input'), $headers['Tosspayments-Webhook-Signature'] ?? '');
$body = json_decode($raw, true);
if ($body['eventType'] === 'PAYMENT_STATUS_CHANGED') { mark_paid(); }
