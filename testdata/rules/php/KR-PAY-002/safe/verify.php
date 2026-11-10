<?php
// portone webhook: Standard Webhooks 라이브러리로 서명을 확인한다
$raw = file_get_contents('php://input');
$wh = new Webhook($secret);
$payload = $wh->verify($raw, $headers);
