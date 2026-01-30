<?php
// upload.php - File upload handler
// Allows users to upload documents

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo '<form method="POST" enctype="multipart/form-data">';
    echo '<input type="file" name="doc">';
    echo '<button type="submit">Upload</button>';
    echo '</form>';
    exit;
}

if (!isset($_FILES['doc']) || $_FILES['doc']['error'] !== UPLOAD_ERR_OK) {
    echo "Upload failed.";
    exit;
}

$upload_dir = "uploads/";
if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755); }
move_uploaded_file($_FILES['doc']['tmp_name'], "uploads/" . $_FILES['doc']['name']);

echo "File uploaded successfully: " . $_FILES['doc']['name'];
echo "<br><a href='index.php'>Back to Home</a>";
?>
