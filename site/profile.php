<?php
session_start();
require "config.php";

// Vérifier si l'utilisateur est connecté
if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit();
}

//  Partie normale : on récupère les infos du compte connecté (sécurisé)
$stmt = $pdo->prepare("SELECT id, username, created_at FROM users WHERE id=?");
$stmt->execute([$_SESSION["user_id"]]);
$account = $stmt->fetch();

// PARTIE VULNÉRABLE POUR SQLMAP  
// ----------------------------------------------------
// Ici on lit un paramètre GET qui n'est PAS filtré
// Exemple : profile.php?id=1 OR 1=1
// ----------------------------------------------------
$id = $_GET['id'] ?? 1; // valeur par défaut

//  Requête SQL VULNÉRABLE
$query = "SELECT * FROM users WHERE id = $id";

// Exécution directe → SQL injection exploitable
$result = $pdo->query($query);
$user = $result->fetch();
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Profil utilisateur</title>
</head>
<body>

<h1>Bienvenue, <?php echo htmlspecialchars($account['username']); ?> !</h1>

<h2> Informations extraites par SQL injection</h2>

<?php if ($user): ?>
    <p><strong>ID :</strong> <?php echo $user["id"]; ?></p>
    <p><strong>Nom d'utilisateur :</strong> <?php echo $user["username"]; ?></p>
    <p><strong>Date de création :</strong> <?php echo $user["created_at"]; ?></p>
<?php else: ?>
    <p>Aucun utilisateur trouvé.</p>
<?php endif; ?>

<hr>

<p><strong>Requête SQL exécutée :</strong>  
<code><?php echo $query; ?></code></p>

<a href="logout.php">Déconnexion</a>

</body>
</html>
