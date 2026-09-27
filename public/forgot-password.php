<?php
require_once '../includes/security.php';
init_secure_session();
require_once '../includes/dbconn.php';

ensure_password_resets_table($conn);

if (!empty($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}

$errors = [];
$submitted = false;
$reset_url = '';
$old = ['email' => ''];
$csrf_token = generate_csrf_token();
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

function passvault_public_reset_url(string $token): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '/passvault/public/forgot-password.php');
    $dir = rtrim(dirname($script), '/');
    return $scheme . '://' . $host . $dir . '/reset.php?token=' . rawurlencode($token);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    list($allowed, $wait_mins) = check_login_rate_limit($ip, 5, 300, 'reset');
    if (!$allowed) {
        $errors[] = "Too many reset requests. Please wait {$wait_mins} minute(s) before trying again.";
    } elseif (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $errors[] = "Security token mismatch. Please try again.";
    } else {
        $email = trim($_POST['email'] ?? '');
        $old['email'] = $email;
        record_failed_login($ip, 300, 'reset');

        $token = bin2hex(random_bytes(32));
        $token_hash = hash('sha256', $token);

        $user_id = null;
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
            if ($stmt) {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $stmt->bind_result($found_id);
                if ($stmt->fetch()) {
                    $user_id = (int) $found_id;
                }
                $stmt->close();
            }
        }

        usleep(random_int(50000, 150000));

        if ($user_id !== null) {
            $expires_at = date('Y-m-d H:i:s', time() + 1800);
            $insert = $conn->prepare("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
            if ($insert) {
                $insert->bind_param("iss", $user_id, $token_hash, $expires_at);
                $insert->execute();
                $insert->close();
            }
        }

        $reset_url = passvault_public_reset_url($token);
        $submitted = true;
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
  <title>Forgot password - PassVault</title>
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

    <p class="lead">Reset your login password. This does not change your vault encryption key.</p>

    <?php if (!empty($errors)): ?>
    <div class="errors">
      <?php foreach ($errors as $e) echo "<div>".htmlspecialchars($e)."</div>"; ?>
    </div>
    <?php endif; ?>

    <?php if ($submitted): ?>
    <div class="errors" style="background: rgba(16,185,129,0.10); border-color: rgba(16,185,129,0.25); color: #047857;">
      If an account exists for that email, you can continue with the reset link below.
    </div>

    <div class="errors" style="background: rgba(15,23,42,0.04); border-color: rgba(15,23,42,0.08); color: #334155;">
      <div style="font-weight: 600; margin-bottom: 8px;">Mail is not configured — local demo only</div>
      <div style="word-break: break-all; font-size: 12px; line-height: 1.5;">
        <a href="<?= htmlspecialchars($reset_url) ?>" style="color: var(--accent);"><?= htmlspecialchars($reset_url) ?></a>
      </div>
    </div>

    <div class="auth-footer">
      <a href="login.php" style="color: var(--accent); text-decoration: none; font-weight: 600;">Back to login</a>
    </div>
    <?php else: ?>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" class="input" required value="<?= htmlspecialchars($old['email']) ?>" placeholder="your@email.com">
      </div>

      <button type="submit" class="btn-primary">Send reset link</button>
    </form>

    <div class="auth-footer">
      Remembered your password? <a href="login.php" style="color: var(--accent); text-decoration: none; font-weight: 600;">Sign in</a>
    </div>
    <?php endif; ?>
  </div>
</div>

</body>
</html>
