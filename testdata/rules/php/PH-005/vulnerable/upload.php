<?php
// 사용자가 보낸 파일 이름을 그대로 쓰는 예
move_uploaded_file($_FILES['f']['tmp_name'], "up/" . $_FILES['f']['name']);
