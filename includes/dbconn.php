<?php
// Load local config if present
if (file_exists(__DIR__ . '/../private/dbconfig.php')) {
    require_once __DIR__ . '/../private/dbconfig.php';
}

// Fallback to Environment Variables (for Railway, Render, Docker, Heroku, etc.)
if (!defined('DB_SERVER')) {
    define('DB_SERVER', getenv('DB_HOST') ?: getenv('MYSQLHOST') ?: 'localhost');
}
if (!defined('DB_USERNAME')) {
    define('DB_USERNAME', getenv('DB_USER') ?: getenv('MYSQLUSER') ?: 'root');
}
if (!defined('DB_PASSWORD')) {
    define('DB_PASSWORD', getenv('DB_PASS') ?: getenv('MYSQLPASSWORD') ?: '');
}
if (!defined('DB_NAME')) {
    define('DB_NAME', getenv('DB_NAME') ?: getenv('MYSQLDATABASE') ?: 'passvault');
}
if (!defined('DB_PORT')) {
    define('DB_PORT', intval(getenv('DB_PORT') ?: getenv('MYSQLPORT') ?: 3306));
}

// Turn off default mysqli exception reporting to prevent stack trace disclosures
mysqli_report(MYSQLI_REPORT_OFF);

$conn = @mysqli_connect(
    DB_SERVER,
    DB_USERNAME,
    DB_PASSWORD,
    DB_NAME,
    DB_PORT
);

if (!$conn) {
    error_log("Database connection error: " . mysqli_connect_error());
    die("A secure database connection could not be established. Please try again later.");
}

$conn->set_charset('utf8mb4');
?>