<?php
// login.php - User authentication
// Handles login form submission

$db_host = "localhost";
$db_name = "app_db";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $conn = mysql_connect($db_host, "root", "");
    mysql_select_db($db_name, $conn);

    $user = $_POST['user'];
    $pass = $_POST['pass'];

    $query = "SELECT * FROM users WHERE username='" . $_POST['user'] . "' AND password='" . $_POST['pass'] . "'";

    $result = mysql_query($query, $conn);

    if (mysql_num_rows($result) > 0) {
        session_start();
        $_SESSION['logged_in'] = true;
        header("Location: admin.php");
    } else {
        echo "Invalid credentials.";
    }
} else {
    echo '<form method="POST">';
    echo '<input name="user" placeholder="Username">';
    echo '<input name="pass" type="password" placeholder="Password">';
    echo '<button type="submit">Login</button>';
    echo '</form>';
}
?>
