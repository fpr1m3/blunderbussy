<?php
// safe_query.php - Secure database query example
// Demonstrates proper use of PDO prepared statements

require_once 'config.php';

$pdo = get_db_connection();

$username = $_GET['user'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user) {
    echo "User found: " . htmlspecialchars($user['username']);
} else {
    echo "User not found.";
}
?>
