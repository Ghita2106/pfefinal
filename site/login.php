<?php
session_start();
require "config.php";
$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST["username"]);
    $password = $_POST["password"];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user["password"])) {
        // créer session
        $_SESSION["user_id"] = $user["id"];
        $_SESSION["username"] = $user["username"];

        header("Location: profile.php");
        exit();
    } else {
        $message = "Nom d'utilisateur ou mot de passe incorrect.";
    }
}
?>

<!DOCTYPE html>
<html>
<head><title>Connexion</title></head>
<body>
<h1>Connexion</h1>
<p><?php echo $message; ?></p>

<form method="POST">
    <label>Nom d'utilisateur :</label><br>
    <input type="text" name="username"><br><br>

    <label>Mot de passe :</label><br>
    <input type="password" name="password"><br><br>

    <button type="submit">Se connecter</button>
</form>

</body>
</html>

