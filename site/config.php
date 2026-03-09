<?php
$dbFile = __DIR__ . "/data/database.db";

try {
    $pdo = new PDO("sqlite:$dbFile");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die("Erreur de connexion à SQLite : " . $e->getMessage());
}
?>
