<?php
require "config.php";
$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"]);
    $password = password_hash($_POST["password"], PASSWORD_DEFAULT);

    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute([$username, $password]);
        $message = "Compte créé avec succès !";
    } catch (Exception $e) {
        $message = "Nom déjà utilisé.";
    }
}
?>

<!DOCTYPE html>
<html>
<head><title>Inscription SQLite</title></head>
<body>
<h1>Créer un compte</h1>
<p><?php echo $message; ?></p>

<form method="post">
    <input name="username" placeholder="Nom"><br><br>
    <input name="password" placeholder="Mot de passe" type="password"><br><br>
    <button type="submit">Créer</button>
</form>

</body>
</html>
