<?php
// 저장 이름을 서버에서 만드는 예
move_uploaded_file($_FILES['f']['tmp_name'], "up/" . bin2hex(random_bytes(16)) . ".jpg");
