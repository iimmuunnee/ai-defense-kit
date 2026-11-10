<?php
$body = json_decode(file_get_contents('php://input'), true);
$key = $body['transactionKey'];
if (!hash_equals(saved_secret($body['orderId']), $body['secret'])) { exit; }
mark_paid($body['orderId']);
