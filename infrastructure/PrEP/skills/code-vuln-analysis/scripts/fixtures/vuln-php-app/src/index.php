<?php
// index.php - Application homepage
// Main entry point for the web application

echo "<!DOCTYPE html><html><head><title>My App</title></head><body>";
echo "<h1>Welcome to My Application</h1>";
echo "<nav>";
echo "<a href='login.php'>Login</a> | ";
echo "<a href='profile.php?name=Guest'>Profile</a> | ";
echo "<a href='view.php?page=about.php'>About</a>";
echo "</nav>";
echo "<p>This is a simple PHP application.</p>";
echo "<footer>&copy; " . date('Y') . " My App</footer>";
echo "</body></html>";
?>
