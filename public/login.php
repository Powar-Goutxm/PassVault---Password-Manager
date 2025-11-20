<?php
session_start();
require_once '../includes/dbconn.php';

$errors = [];
$old = ['email' => ''];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"]);
    $password = $_POST["password"];
    $old['email'] = $email;

    $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 1) {
        $stmt->bind_result($id, $hash);
        $stmt->fetch();

        if (password_verify($password, $hash)) {
            session_regenerate_id(true);
            $_SESSION["user_id"] = $id;
            $_SESSION["user_email"] = $email;
            header("Location: dashboard.php");
            exit;
        }
    }

    $errors[] = "Invalid email or password.";
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../assets/css/style.css">
  <title>Login - PassVault</title>
</head>
<body>

<div class="bg-orbs"></div>

<div class="page-wrap">
  <div class="auth-card">
    <div class="auth-top">
      <div class="brand-bubble">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div>
        <h1>PassVault</h1>
      </div>
    </div>

    <p class="lead">Sign in to access your secure password vault</p>

    <?php if (!empty($errors)): ?>
    <div class="errors">
      <?php foreach ($errors as $e) echo "<div>".htmlspecialchars($e)."</div>"; ?>
    </div>
    <?php endif; ?>

    <form method="post">
      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" class="input" required value="<?= htmlspecialchars($old['email']) ?>" placeholder="your@email.com">
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" class="input" required placeholder="Enter your password">
      </div>

      <div class="help-row">
        <span></span>
        <a href="forgot-password.php" style="text-decoration: none; color: var(--muted);">Forgot password?</a>
      </div>

      <button type="submit" class="btn-primary">Sign In</button>
    </form>

    <div class="auth-footer">
      Don't have an account? <a href="register.php" style="color: var(--accent); text-decoration: none; font-weight: 600;">Register Now</a>
    </div>
  </div>
</div>

</body>
</html>