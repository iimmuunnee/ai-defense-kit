<?php
$_SESSION['state'] = $csrf;
header('Location: https://nid.naver.com/oauth2.0/authorize?' . http_build_query($q));
