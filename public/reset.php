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
$link_invalid = false;
$csrf_token = generate_csrf_token();
$raw_token = $_GET['token'] ?? ($_POST['token'] ?? '');
$raw_token = is_string($raw_token) ? trim($raw_token) : '';

function password_reset_token_valid_format(string $token): bool {
    return (bool) preg_match('/^[a-f0-9]{64}$/', $token);
}

if (!password_reset_token_valid_format($raw_token)) {
    $link_invalid = true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $errors[] = "Security token mismatch. Please try again.";
    } elseif ($link_invalid) {
        $errors[] = "This reset link is invalid or has expired.";
    } else {
        $password = $_POST['password'] ?? '';
        $password_confirm = $_POST['password_confirm'] ?? '';

        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters.";
        }
        if ($password !== $password_confirm) {
            $errors[] = "Passwords do not match.";
        }

        if (empty($errors)) {
            $token_hash = hash('sha256', $raw_token);
            $stmt = $conn->prepare("SELECT id, user_id FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW() LIMIT 1");
            $reset_id = null;
            $user_id = null;
            if ($stmt) {
                $stmt->bind_param("s", $token_hash);
                $stmt->execute();
                $stmt->bind_result($reset_id, $user_id);
                if (!$stmt->fetch()) {
                    $reset_id = null;
                    $user_id = null;
                }
                $stmt->close();
            }

            if ($reset_id === null) {
                $link_invalid = true;
                $errors[] = "This reset link is invalid or has expired.";
            } else {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $conn->begin_transaction();
                $upd = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                $mark = $conn->prepare("UPDATE password_resets SET used_at = NOW() WHERE id = ?");
                $ok = false;
                if ($upd && $mark) {
                    $upd->bind_param("si", $password_hash, $user_id);
                    $mark->bind_param("i", $reset_id);
                    $ok = $upd->execute() && $mark->execute();
                    $upd->close();
                    $mark->close();
                }
                if ($ok) {
                    $conn->commit();
                    header("Location: login.php?reset=1");
                    exit;
                }
                $conn->rollback();
                $link_invalid = true;
                $errors[] = "This reset link is invalid or has expired.";
            }
        }
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
  <title>Reset password - PassVault</title>
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

    <p class="lead">Choose a new login password. Vault items are not re-encrypted.</p>

    <?php if (!empty($errors) || ($link_invalid && $_SERVER['REQUEST_METHOD'] !== 'POST')): ?>
    <div class="errors">
      <?php if (!empty($errors)): ?>
        <?php foreach ($errors as $e) echo "<div>".htmlspecialchars($e)."</div>"; ?>
      <?php else: ?>
        <div>This reset link is invalid or has expired.</div>
      <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php if (!$link_invalid): ?>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
      <input type="hidden" name="token" value="<?= htmlspecialchars($raw_token) ?>">

      <div class="field">
        <label for="password">New password</label>
        <input type="password" id="password" name="password" class="input" required minlength="8" placeholder="At least 8 characters">
      </div>

      <div class="field">
        <label for="password_confirm">Confirm password</label>
        <input type="password" id="password_confirm" name="password_confirm" class="input" required minlength="8" placeholder="Re-type your new password">
      </div>

      <button type="submit" class="btn-primary">Update password</button>
    </form>
    <?php else: ?>
    <div class="auth-footer">
      <a href="forgot-password.php" style="color: var(--accent); text-decoration: none; font-weight: 600;">Request a new link</a>
    </div>
    <?php endif; ?>

    <div class="auth-footer">
      <a href="login.php" style="color: var(--muted); text-decoration: none;">Back to login</a>
    </div>
  </div>
</div>

</body>
</html>
