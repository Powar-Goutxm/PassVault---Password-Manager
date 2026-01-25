<?php
session_start();
require_once '../includes/dbconn.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = intval($_SESSION['user_id']);
$message = '';
$error = '';

// Fetch user data
$stmt = $conn->prepare("SELECT email FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

// Handle password change
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'change_password') {
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Fetch current password hash
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();

    if (!password_verify($current_password, $row['password_hash'])) {
        $error = "Current password is incorrect.";
    } elseif (strlen($new_password) < 8) {
        $error = "New password must be at least 8 characters.";
    } elseif ($new_password !== $confirm_password) {
        $error = "Passwords do not match.";
    } else {
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->bind_param("si", $password_hash, $user_id);
        if ($stmt->execute()) {
            $message = "Password changed successfully.";
        } else {
            $error = "Failed to change password.";
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings — PassVault</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <link rel="stylesheet" href="../assets/css/dashboard.css">
    <style>
        body {
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.08) 0%, rgba(244, 114, 182, 0.06) 100%);
            min-height: 100vh;
        }
    </style>
</head>
<body>

<?php require_once '../includes/header.php'; ?>

<main class="dashboard-main container">
    <h1>Settings</h1>

    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <?php if (!empty($error)): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <!-- Account Section -->
    <section class="card">
        <h2>Account Information</h2>
        <div style="display: flex; align-items: center; gap: 12px; margin: 16px 0;">
            <div style="width: 60px; height: 60px; border-radius: 50%; background: linear-gradient(135deg, #06b6d4, #f472b6); display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 700; font-size: 24px;">
                <?= strtoupper(substr($user['email'], 0, 1)) ?>
            </div>
            <div>
                <p style="margin: 0; font-weight: 600;"><?= htmlspecialchars($user['email']) ?></p>
                <p style="margin: 4px 0 0; color: #6b7280; font-size: 13px;">Active account</p>
            </div>
        </div>
    </section>

    <!-- Change Password Section -->
    <section class="card" style="margin-top: 24px;">
        <h2>Change Password</h2>
        <form method="post" style="max-width: 400px;">
            <input type="hidden" name="action" value="change_password">
            
            <div class="field">
                <label for="current_password">Current Password</label>
                <input type="password" id="current_password" name="current_password" class="input" required>
            </div>

            <div class="field">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" class="input" required placeholder="Minimum 8 characters">
            </div>

            <div class="field">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" class="input" required>
            </div>

            <button type="submit" class="btn pill primary" style="margin-top: 12px;">Change Password</button>
        </form>
    </section>

    <!-- About Section -->
    <section class="card" style="margin-top: 24px;">
        <h2>About PassVault</h2>
        <p style="color: #6b7280; line-height: 1.6;">
            PassVault is a modern, secure password manager built with AES-256 encryption. 
            All your passwords are encrypted locally before being stored, ensuring your data remains private and secure.
        </p>
        <p style="color: #6b7280; font-size: 13px; margin-top: 16px;">
            <strong>Version:</strong> 1.0.0<br>
            <strong>Last Updated:</strong> November 2025
        </p>
    </section>

    <!-- Security Tips Section -->
    <section class="card" style="margin-top: 24px; margin-bottom: 60px;">
        <h2>Security Tips</h2>
        <ul style="color: #6b7280; line-height: 1.8; padding-left: 20px;">
            <li>Use a strong, unique password for your PassVault account</li>
            <li>Never share your master password with anyone</li>
            <li>Keep your browser and system updated</li>
            <li>Log out after each session on shared devices</li>
            <li>Enable two-factor authentication when available</li>
        </ul>
    </section>

</main>

</body>
</html>
