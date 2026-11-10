<?php
$body = json_decode(file_get_contents('php://input'), true);
$key = $body['transactionKey'];
$value = $body['secret'];
mark_paid($body['orderId']);
