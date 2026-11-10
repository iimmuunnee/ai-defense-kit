<?php
$_SESSION['state'] = $csrf;
header('Location: https://kauth.kakao.com/oauth/authorize?' . http_build_query($q));
