<?php
require_once __DIR__ . '/../private/dbconfig.php';

$conn = mysqli_connect(
    DB_SERVER,
    DB_USERNAME,
    DB_PASSWORD,
    DB_NAME
);

if ($conn === false) {
    die("ERROR: Could not connect. " . mysqli_connect_error());
}

$conn->set_charset('utf8mb4');
