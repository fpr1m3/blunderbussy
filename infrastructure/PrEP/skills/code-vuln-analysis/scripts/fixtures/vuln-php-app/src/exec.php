<?php
// exec.php - Network diagnostic tool
// Pings a host provided by the user

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo '<form method="POST"><input name="host" placeholder="Hostname"><button>Ping</button></form>';
    exit;
}

system("ping -c 4 " . $_POST['host']);

echo "<br>Ping complete.";
?>
