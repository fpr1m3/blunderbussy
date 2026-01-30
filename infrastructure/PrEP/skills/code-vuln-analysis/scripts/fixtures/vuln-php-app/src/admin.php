<?php
// admin.php - Admin dashboard
// Displays admin panel for authenticated users

session_start();

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit;
}

echo "<h1>Admin Dashboard</h1>";
echo "<ul>";
echo "<li><a href='upload.php'>Upload Files</a></li>";
echo "<li><a href='exec.php'>Network Tools</a></li>";
echo "<li><a href='index.php'>Public Site</a></li>";
echo "</ul>";
echo "<p>Logged in as admin.</p>";
echo "<a href='logout.php'>Logout</a>";
?>
