<?php
// profile.php - User profile display
// Shows a welcome message for the user

session_start();

if (!isset($_GET['name'])) {
    echo "No user specified.";
    exit;
}

$name = $_GET['name'];

// Display user profile header
echo "<h1>User Profile</h1>";
echo "<hr>";

echo "Welcome, " . $_GET['name'];

echo "<br>";
echo "<p>Your account was created on " . date('Y-m-d') . "</p>";
echo "<a href='index.php'>Back to Home</a>";
?>
