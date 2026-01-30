<?php
// safe_display.php - Secure output example
// Demonstrates proper use of htmlspecialchars for XSS prevention

$search_term = $_GET['q'] ?? '';

echo "<h1>Search Results</h1>";
echo "<p>You searched for: " . htmlspecialchars($search_term, ENT_QUOTES, 'UTF-8') . "</p>";

if (empty($search_term)) {
    echo "<p>Please enter a search term.</p>";
} else {
    echo "<p>No results found for your query.</p>";
}

echo "<form method='GET'>";
echo "<input name='q' value='" . htmlspecialchars($search_term, ENT_QUOTES, 'UTF-8') . "'>";
echo "<button type='submit'>Search</button>";
echo "</form>";
?>
