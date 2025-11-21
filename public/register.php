<?php
session_start();
require_once '../includes/dbconn.php';

$errors = [];
$old = ['email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';

    $old['email'] = $email;

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Enter a valid email.";
    }
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters.";
    }
    if ($password !== $password_confirm) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $errors[] = "Email is already registered.";
        }
        $stmt->close();
    }

    if (empty($errors)) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $insert = $conn->prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)");
        $insert->bind_param("ss", $email, $password_hash);

        if ($insert->execute()) {
            session_regenerate_id(true);
            $_SESSION["user_id"] = $insert->insert_id;
            $_SESSION["user_email"] = $email;
            header("Location: dashboard.php");
            exit;
        } else {
            $errors[] = "Registration failed. Please try again.";
        }
        $insert->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Register - PassVault</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>

<div class="bg-orbs"></div>

<div class="page-wrap">
  <div class="auth-card">
    <div class="auth-top">
      <div class="brand-bubble" aria-hidden="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
             stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div>
        <h1>PassVault</h1>
      </div>
    </div>

    <p class="lead">Create an account to securely store your passwords.</p>

    <?php if (!empty($errors)): ?>
    <div class="errors" role="alert">
      <?php foreach ($errors as $e): ?>
        <div><?= htmlspecialchars($e) ?></div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <form method="post" novalidate>
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" class="input" required
               value="<?= htmlspecialchars($old['email']) ?>" placeholder="you@example.com">
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" class="input" required
               placeholder="Create a strong password (min 8 chars)">
      </div>

      <div class="field">
        <label for="password_confirm">Confirm Password</label>
        <input id="password_confirm" name="password_confirm" type="password" class="input" required
               placeholder="Re-type your password">
      </div>

   <div class="help-row" style="margin-top:8px; margin-bottom:12px;">
  
</div>

<button type="submit" class="btn-primary" style="margin-top:6px;">
  Create Account
</button>

<div class="auth-footer" style="margin-top:18px;">
  Already have an account?
  <a href="login.php" style="color:var(--accent); text-decoration:none; font-weight:600;">
    Log in
  </a>
</div>

  </div>
</div>

</body>
</html>
