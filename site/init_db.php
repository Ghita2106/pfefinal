<?php
$dbFile = __DIR__ . "/data/database.db";

try {
    $db = new PDO("sqlite:$dbFile");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )";

    $db->exec($sql);
    echo "Base SQLite initialisée avec succès.";
} catch (Exception $e) {
    echo "Erreur : " . $e->getMessage();
}
