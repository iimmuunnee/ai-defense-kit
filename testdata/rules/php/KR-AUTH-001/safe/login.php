<?php
$params = http_build_query(['client_id' => $id, 'redirect_uri' => $uri, 'response_type' => 'code', 'state' => $csrf]);
header('Location: https://kauth.kakao.com/oauth/authorize?' . $params);
