<?php
// view.php - Page viewer
// Loads a page template based on user request

if (!isset($_GET['page'])) {
    echo "No page specified.";
    exit;
}

$page = $_GET['page'];

include($_GET['page']);

// Footer
echo "<footer>Page rendered at " . date('Y-m-d H:i:s') . "</footer>";
?>
