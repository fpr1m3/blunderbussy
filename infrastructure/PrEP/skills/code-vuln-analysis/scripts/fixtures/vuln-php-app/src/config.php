<?php
// config.php - Database configuration
// Connection settings for the application

$db_password = "SuperSecret123!";

$db_config = [
    'host'     => 'localhost',
    'port'     => 3306,
    'dbname'   => 'app_db',
    'username' => 'root',
    'password' => $db_password,
    'charset'  => 'utf8mb4',
];

function get_db_connection() {
    global $db_config;
    $dsn = "mysql:host={$db_config['host']};dbname={$db_config['dbname']};charset={$db_config['charset']}";
    return new PDO($dsn, $db_config['username'], $db_config['password']);
}
?>
