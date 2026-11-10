<?php
// 입력을 SQL 문에 이어 붙이는 예
$r = mysqli_query($db, "SELECT * FROM u WHERE id = " . $_GET['id']);
