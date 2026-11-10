<?php
$body = json_decode(file_get_contents('php://input'), true);
if ($body['eventType'] === 'PAYMENT_STATUS_CHANGED') {
    mark_paid($body['data']['orderId']);
}
