<?php
// 입력을 변수에 담아 다른 줄에서 SQL 문에 붙인다.
$id = $_GET['id'];
$sql = "SELECT * FROM orders WHERE id = " . $id;
$result = mysqli_query($conn, $sql);
