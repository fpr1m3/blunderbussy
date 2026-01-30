<?php
// download.php - File download handler
// Serves files from the uploads directory

if (!isset($_GET['file'])) {
    echo "No file specified.";
    exit;
}

$filename = $_GET['file'];

header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename=\"" . basename($filename) . "\"");
$content = file_get_contents("uploads/" . $_GET['file']);

echo $content;
?>
