<?php

if (empty($_GET["name"])) {
    die("Name is required");
}

if ( ! filter_var($_GET["email"], FILTER_VALIDATE_EMAIL)) {
    die("Valid email is required");
}

if (strlen($_GET["password"]) < 8) {
    die("Password must be at least 8 characters");
}

if ( ! preg_match("/[a-z]/i", $_GET["password"])) {
    die("Password must contain at least one letter");
}

if ( ! preg_match("/[0-9]/", $_GET["password"])) {
    die("Password must contain at least one number");
}

if ($_GET["password"] !== $_GET["password_confirmation"]) {
    die("Passwords must match");
}

$password_hash = password_hash($_GET["password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

$sql = "INSERT INTO user (name, email, password_hash)
        VALUES (?, ?, ?)";
        
$stmt = $mysqli->stmt_init();

if ( ! $stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("sss",
                  $_GET["name"],
                  $_GET["email"],
                  $password_hash);
                  
if ($stmt->execute()) {

    header("Location: signup-success.html");
    exit;
    
} else {
    
    if ($mysqli->errno === 1062) {
        die("email already taken");
    } else {
        die($mysqli->error . " " . $mysqli->errno);
    }
}
