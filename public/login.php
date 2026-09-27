<?php
require_once '../includes/security.php';
init_secure_session();
require_once '../includes/dbconn.php';

if (!empty($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}

$errors = [];
$old = ['email' => ''];
$csrf_token = generate_csrf_token();
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // 1. Rate Limiting Check (SEC-07 Remediation)
    list($allowed, $wait_mins) = check_login_rate_limit($ip, 5, 300);
    if (!$allowed) {
        $errors[] = "Too many failed attempts. Please wait {$wait_mins} minute(s) before trying again.";
    } elseif (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        // 2. CSRF Token Verification (SEC-03 Remediation)
        $errors[] = "Security token mismatch. Please try again.";
    } else {
        $email = trim($_POST["email"] ?? '');
        $password = $_POST["password"] ?? '';
        $old['email'] = $email;

        $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE email = ?");
        if ($stmt) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 1) {
                $stmt->bind_result($id, $hash);
                $stmt->fetch();

                if (password_verify($password, $hash)) {
                    // Reset rate limit on success
                    clear_failed_logins($ip);

                    // Prevent session fixation (SEC-06 Remediation)
                    session_regenerate_id(true);
                    $_SESSION["user_id"] = $id;
                    $_SESSION["user_email"] = $email;
                    header("Location: dashboard.php");
                    exit;
                }
            }
            $stmt->close();
        }

        // Record failed attempt
        record_failed_login($ip, 300);
        $errors[] = "Invalid email or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../assets/css/auth.css">
  <title>Login - PassVault</title>
</head>
<body class="auth-body">

<div class="auth-mesh" aria-hidden="true"></div>

<div class="page-wrap">
  <div class="auth-card">
    <div class="auth-top">
      <a href="./index.php">
        <div class="brand-bubble">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <h1>PassVault</h1>
      </a>
    </div>

    <p class="lead">Sign in to access your secure password vault</p>

    <?php if (isset($_GET['reset']) && $_GET['reset'] === '1'): ?>
    <div class="errors notice-ok">
      Your login password was updated. Sign in with your new password.
    </div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
    <div class="errors">
      <?php foreach ($errors as $e) echo "<div>".htmlspecialchars($e)."</div>"; ?>
    </div>
    <?php endif; ?>

    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

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
        <a href="forgot-password.php">Forgot password?</a>
      </div>

      <button type="submit" class="btn-primary">Sign In</button>
    </form>

    <div class="auth-footer">
      Don't have an account? <a href="register.php">Register Now</a>
    </div>
  </div>
</div>

</body>
</html>