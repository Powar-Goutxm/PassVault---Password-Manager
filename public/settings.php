<?php
require_once '../includes/security.php';
init_secure_session();
require_once '../includes/dbconn.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = intval($_SESSION['user_id']);
$message = '';
$error = '';
$csrf_token = generate_csrf_token();

// Fetch user data
$stmt = $conn->prepare("SELECT email FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

// Handle password change
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'change_password') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Security token mismatch. Please try again.";
    } else {
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

        if (!$row || !password_verify($current_password, $row['password_hash'])) {
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
                // Regenerate session to invalidate any older session handles (SEC-09)
                session_regenerate_id(true);
                unset($_SESSION['csrf_token']);
                $csrf_token = generate_csrf_token();
                $message = "Password changed successfully.";
            } else {
                $error = "Failed to change password.";
            }
            $stmt->close();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Settings — PassVault</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/theme.css">
    <link rel="stylesheet" href="../assets/css/header.css">
    <link rel="stylesheet" href="../assets/css/dashboard.css">
    <style>
        /* Scoped Obsidian Glassmorphism Settings Layout */
        body.settings-page {
            margin: 0;
            min-height: 100vh;
            font-family: var(--pv-font);
            color: var(--pv-text);
            background-color: var(--pv-bg);
            background-image: none;
            -webkit-font-smoothing: antialiased;
            position: relative;
        }

        .settings-mesh {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            background:
                radial-gradient(ellipse 70% 50% at 15% 10%, var(--pv-glow-indigo), transparent 58%),
                radial-gradient(ellipse 50% 40% at 90% 85%, var(--pv-glow-cyan), transparent 55%),
                radial-gradient(circle at 50% 50%, #0c0c14 0%, var(--pv-bg) 70%);
        }

        .settings-container {
            position: relative;
            z-index: 1;
            max-width: 1200px;
            margin: 0 auto;
            padding: 36px 20px 80px;
        }

        .settings-header-banner {
            margin-bottom: 32px;
        }

        .settings-title {
            font-family: var(--pv-display);
            font-size: 32px;
            font-weight: 700;
            color: var(--pv-text);
            margin: 0 0 8px 0;
            display: flex;
            align-items: center;
            gap: 12px;
            letter-spacing: -0.5px;
        }

        .settings-title-gradient {
            background: linear-gradient(135deg, var(--pv-cyan) 0%, var(--pv-indigo-hot) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .settings-subtitle {
            margin: 0;
            color: var(--pv-text-muted);
            font-size: 14px;
            line-height: 1.5;
        }

        /* Dark Frosted Glass Alerts */
        .alert {
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 16px 20px;
            border-radius: var(--pv-radius);
            margin-bottom: 28px;
            font-size: 14px;
            line-height: 1.5;
            backdrop-filter: blur(var(--pv-blur));
            -webkit-backdrop-filter: blur(var(--pv-blur));
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
        }

        .alert-icon {
            flex-shrink: 0;
            width: 22px;
            height: 22px;
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(52, 211, 153, 0.35);
            color: var(--pv-ok);
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(248, 113, 113, 0.35);
            color: var(--pv-danger);
        }

        /* 2-Column Responsive Layout */
        .settings-grid {
            display: grid;
            grid-template-columns: 1.15fr 0.85fr;
            gap: 28px;
            align-items: start;
        }

        @media (max-width: 960px) {
            .settings-grid {
                grid-template-columns: 1fr;
                gap: 24px;
            }
        }

        /* Glass Cards */
        .glass-card {
            background: var(--pv-glass-strong);
            border: 1px solid var(--pv-glass-border);
            backdrop-filter: blur(var(--pv-blur));
            -webkit-backdrop-filter: blur(var(--pv-blur));
            border-radius: var(--pv-radius);
            padding: 28px;
            box-shadow: var(--pv-shadow), 0 0 0 1px rgba(34, 211, 238, 0.04);
            margin-bottom: 28px;
        }

        .glass-card:last-child {
            margin-bottom: 0;
        }

        .card-head {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--pv-line);
        }

        .card-head-icon {
            width: 38px;
            height: 38px;
            border-radius: 10px;
            background: rgba(99, 102, 241, 0.14);
            border: 1px solid var(--pv-glass-border);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--pv-cyan);
            flex-shrink: 0;
        }

        .card-head-title {
            font-family: var(--pv-display);
            font-size: 19px;
            font-weight: 700;
            color: var(--pv-text);
            margin: 0;
        }

        .card-head-subtitle {
            font-size: 13px;
            color: var(--pv-text-muted);
            margin: 2px 0 0 0;
        }

        /* Account Info Section */
        .account-badge-row {
            display: flex;
            align-items: center;
            gap: 18px;
            margin-bottom: 24px;
        }

        .account-avatar {
            width: 64px;
            height: 64px;
            border-radius: 18px;
            background: linear-gradient(135deg, var(--pv-cyan) 0%, var(--pv-indigo) 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #041016;
            font-family: var(--pv-display);
            font-weight: 800;
            font-size: 26px;
            box-shadow: 0 8px 24px rgba(34, 211, 238, 0.25), inset 0 1px 1px rgba(255, 255, 255, 0.4);
            flex-shrink: 0;
        }

        .account-details {
            flex: 1;
            min-width: 0;
        }

        .account-email-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: var(--pv-text-dim);
            margin-bottom: 4px;
            font-weight: 600;
        }

        .account-email-value {
            font-size: 17px;
            font-weight: 600;
            color: var(--pv-text);
            word-break: break-all;
            margin-bottom: 8px;
        }

        .vault-status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 5px 12px;
            border-radius: 999px;
            background: rgba(52, 211, 153, 0.1);
            border: 1px solid rgba(52, 211, 153, 0.28);
            color: var(--pv-ok);
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.2px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--pv-ok);
            box-shadow: 0 0 10px rgba(52, 211, 153, 0.7);
            display: inline-block;
        }

        .account-meta-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            padding-top: 16px;
            border-top: 1px solid var(--pv-line);
        }

        .meta-stat-box {
            background: rgba(7, 7, 11, 0.45);
            border: 1px solid var(--pv-line);
            border-radius: 12px;
            padding: 12px 14px;
        }

        .meta-stat-label {
            font-size: 11px;
            color: var(--pv-text-dim);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }

        .meta-stat-value {
            font-size: 13px;
            color: var(--pv-text-muted);
            font-weight: 600;
        }

        /* Form Controls & Inputs */
        .form-field {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--pv-text);
            margin-bottom: 8px;
            letter-spacing: 0.2px;
        }

        .pv-input {
            width: 100%;
            padding: 13px 16px;
            border-radius: 12px;
            border: 1px solid var(--pv-line);
            background: rgba(7, 7, 11, 0.65);
            outline: none;
            font-size: 14px;
            color: var(--pv-text);
            font-family: inherit;
            box-sizing: border-box;
            transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
        }

        .pv-input:focus {
            border-color: var(--pv-cyan);
            box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.2), 0 0 16px rgba(34, 211, 238, 0.15);
            background: rgba(12, 12, 20, 0.85);
        }

        .pv-input::placeholder {
            color: var(--pv-text-dim);
        }

        /* Password Strength Meter */
        .pw-strength {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-top: 10px;
            margin-bottom: 4px;
            font-size: 12px;
            color: var(--pv-text-muted);
        }

        .pw-bar {
            display: flex;
            gap: 6px;
            flex: 1;
        }

        .pw-bar span {
            flex: 1;
            height: 6px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.08);
            transition: background 0.25s ease, transform 0.2s ease, box-shadow 0.25s ease;
            display: inline-block;
        }

        .pw-bar span.active-1 {
            background: #f87171;
            box-shadow: 0 0 8px rgba(248, 113, 113, 0.45);
        }

        .pw-bar span.active-2 {
            background: #fbbf24;
            box-shadow: 0 0 8px rgba(251, 191, 36, 0.45);
        }

        .pw-bar span.active-3 {
            background: #34d399;
            box-shadow: 0 0 8px rgba(52, 211, 153, 0.45);
        }

        .pw-bar span.active-4 {
            background: #22d3ee;
            box-shadow: 0 0 10px rgba(34, 211, 238, 0.6);
        }

        .pw-label {
            font-weight: 600;
            font-size: 12px;
            letter-spacing: 0.3px;
            white-space: nowrap;
            color: var(--pv-text-dim);
        }

        .pw-label.weak { color: #f87171; }
        .pw-label.medium { color: #fbbf24; }
        .pw-label.strong { color: #34d399; }
        .pw-label.vstrong { color: #22d3ee; }

        /* Primary Update Button */
        .btn-settings-update {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 13px 20px;
            border-radius: 12px;
            border: 1px solid rgba(34, 211, 238, 0.35);
            background: linear-gradient(135deg, var(--pv-cyan) 0%, var(--pv-indigo) 100%);
            color: #041016;
            font-family: var(--pv-display);
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 8px 24px rgba(99, 102, 241, 0.28), 0 0 16px rgba(34, 211, 238, 0.2);
            transition: transform 0.2s ease, box-shadow 0.2s ease, filter 0.2s ease;
            margin-top: 8px;
        }

        .btn-settings-update:hover {
            transform: translateY(-2px);
            filter: brightness(1.08);
            box-shadow: 0 12px 32px rgba(99, 102, 241, 0.36), 0 0 24px rgba(34, 211, 238, 0.3);
        }

        .btn-settings-update:active {
            transform: translateY(0);
        }

        /* Principles List */
        .principles-list {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .principle-item {
            display: flex;
            gap: 14px;
            padding: 14px 16px;
            border-radius: 12px;
            background: rgba(7, 7, 11, 0.45);
            border: 1px solid var(--pv-line);
            transition: border-color 0.2s ease, background 0.2s ease;
        }

        .principle-item:hover {
            border-color: var(--pv-glass-border);
            background: rgba(12, 12, 20, 0.65);
        }

        .principle-icon-badge {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: rgba(34, 211, 238, 0.1);
            border: 1px solid rgba(34, 211, 238, 0.2);
            color: var(--pv-cyan);
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            margin-top: 2px;
        }

        .principle-content h3 {
            margin: 0 0 4px 0;
            font-size: 14px;
            font-weight: 600;
            color: var(--pv-text);
        }

        .principle-content p {
            margin: 0;
            font-size: 12.5px;
            color: var(--pv-text-muted);
            line-height: 1.5;
        }

        /* Technical Specifications */
        .specs-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0 8px;
        }

        .specs-table tr {
            background: rgba(7, 7, 11, 0.45);
            border-radius: 10px;
        }

        .specs-table td {
            padding: 12px 14px;
            font-size: 13px;
        }

        .specs-table td:first-child {
            border-top-left-radius: 10px;
            border-bottom-left-radius: 10px;
            border: 1px solid var(--pv-line);
            border-right: none;
            color: var(--pv-text-muted);
            font-weight: 500;
            width: 42%;
        }

        .specs-table td:last-child {
            border-top-right-radius: 10px;
            border-bottom-right-radius: 10px;
            border: 1px solid var(--pv-line);
            border-left: none;
            color: var(--pv-cyan);
            font-weight: 600;
            font-family: monospace;
            font-size: 12.5px;
        }

        /* Reduced Motion Compliance */
        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }

            .btn-settings-update:hover {
                transform: none !important;
            }

            .pw-bar span {
                transition: none !important;
                transform: none !important;
            }
        }
    </style>
</head>
<body class="settings-page">

<div class="settings-mesh" aria-hidden="true"></div>

<?php require_once '../includes/header.php'; ?>

<main class="settings-container">
    <header class="settings-header-banner">
        <h1 class="settings-title">
            <span class="settings-title-gradient">Account</span> Settings
        </h1>
        <p class="settings-subtitle">
            Configure your master authentication passphrase, verify zero-knowledge vault protection, and audit session security.
        </p>
    </header>

    <?php if (!empty($message)): ?>
        <div class="alert alert-success" role="alert">
            <svg class="alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <div>
                <strong>Success: </strong><?= htmlspecialchars($message) ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($error)): ?>
        <div class="alert alert-error" role="alert">
            <svg class="alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <div>
                <strong>Security Alert: </strong><?= htmlspecialchars($error) ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="settings-grid">
        <!-- LEFT COLUMN: Account Information & Change Master Password -->
        <div class="settings-col-left">
            <!-- Account Information Card -->
            <section class="glass-card">
                <div class="card-head">
                    <div class="card-head-icon" aria-hidden="true">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                            <circle cx="12" cy="7" r="4"></circle>
                        </svg>
                    </div>
                    <div>
                        <h2 class="card-head-title">Account Information</h2>
                        <p class="card-head-subtitle">Authenticated user profile and credential state</p>
                    </div>
                </div>

                <div class="account-badge-row">
                    <div class="account-avatar" aria-hidden="true">
                        <?= strtoupper(substr($user['email'] ?? 'U', 0, 1)) ?>
                    </div>
                    <div class="account-details">
                        <div class="account-email-label">Registered Master Email</div>
                        <div class="account-email-value"><?= htmlspecialchars($user['email'] ?? '') ?></div>
                        <div class="vault-status-pill">
                            <span class="status-dot"></span>
                            <span>Active Vault · End-to-End Encrypted</span>
                        </div>
                    </div>
                </div>

                <div class="account-meta-grid">
                    <div class="meta-stat-box">
                        <div class="meta-stat-label">Security Role</div>
                        <div class="meta-stat-value">Vault Owner</div>
                    </div>
                    <div class="meta-stat-box">
                        <div class="meta-stat-label">Session Protection</div>
                        <div class="meta-stat-value">HttpOnly & Strict</div>
                    </div>
                </div>
            </section>

            <!-- Change Master Password Card -->
            <section class="glass-card">
                <div class="card-head">
                    <div class="card-head-icon" aria-hidden="true">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                    </div>
                    <div>
                        <h2 class="card-head-title">Change Master Password</h2>
                        <p class="card-head-subtitle">Update your primary credential to re-key vault authentication</p>
                    </div>
                </div>

                <form method="post" action="settings.php" novalidate>
                    <input type="hidden" name="action" value="change_password">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

                    <div class="form-field">
                        <label for="current_password" class="form-label">Current Master Password</label>
                        <input type="password" id="current_password" name="current_password" class="pv-input" required autocomplete="current-password" placeholder="Enter current master password">
                    </div>

                    <div class="form-field">
                        <label for="new_password" class="form-label">New Master Password</label>
                        <input type="password" id="new_password" name="new_password" class="pv-input password-input" required minlength="8" autocomplete="new-password" placeholder="Minimum 8 characters">
                        <div class="pw-strength" aria-live="polite">
                            <div class="pw-bar"><span></span><span></span><span></span><span></span></div>
                            <div class="pw-label">Strength</div>
                        </div>
                    </div>

                    <div class="form-field">
                        <label for="confirm_password" class="form-label">Confirm New Master Password</label>
                        <input type="password" id="confirm_password" name="confirm_password" class="pv-input" required minlength="8" autocomplete="new-password" placeholder="Re-enter new master password">
                    </div>

                    <button type="submit" class="btn-settings-update">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                        Update Master Password
                    </button>
                </form>
            </section>
        </div>

        <!-- RIGHT COLUMN: Vault Security Principles & About PassVault -->
        <div class="settings-col-right">
            <!-- Vault Security Principles Card -->
            <section class="glass-card">
                <div class="card-head">
                    <div class="card-head-icon" aria-hidden="true">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                    </div>
                    <div>
                        <h2 class="card-head-title">Vault Security Principles</h2>
                        <p class="card-head-subtitle">Zero-knowledge guarantees and protocols</p>
                    </div>
                </div>

                <div class="principles-list">
                    <div class="principle-item">
                        <div class="principle-icon-badge" aria-hidden="true">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle>
                                <path d="m4.93 4.93 4.24 4.24"></path>
                                <path d="m14.83 9.17 4.24-4.24"></path>
                                <path d="m14.83 14.83 4.24 4.24"></path>
                                <path d="m9.17 14.83-4.24 4.24"></path>
                            </svg>
                        </div>
                        <div class="principle-content">
                            <h3>Unique Passphrase</h3>
                            <p>Your master passphrase is the master encryption key. It should never be reused across third-party websites or unverified devices.</p>
                        </div>
                    </div>

                    <div class="principle-item">
                        <div class="principle-icon-badge" aria-hidden="true">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                            </svg>
                        </div>
                        <div class="principle-content">
                            <h3>Zero Knowledge AES-256-GCM</h3>
                            <p>Vault secrets are stored using authenticated Galois/Counter Mode encryption. Secrets are decrypted strictly on-demand during active sessions.</p>
                        </div>
                    </div>

                    <div class="principle-item">
                        <div class="principle-icon-badge" aria-hidden="true">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <polyline points="23 4 23 10 17 10"></polyline>
                                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                            </svg>
                        </div>
                        <div class="principle-content">
                            <h3>Session Hygiene</h3>
                            <p>Sessions enforce automated ID regeneration upon credential modification, strict SameSite cookie isolation, and instant key revocation upon logout.</p>
                        </div>
                    </div>
                </div>
            </section>

            <!-- About PassVault Card -->
            <section class="glass-card">
                <div class="card-head">
                    <div class="card-head-icon" aria-hidden="true">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="16" x2="12" y2="12"></line>
                            <line x1="12" y1="8" x2="12.01" y2="8"></line>
                        </svg>
                    </div>
                    <div>
                        <h2 class="card-head-title">About PassVault</h2>
                        <p class="card-head-subtitle">System architecture and technical specifications</p>
                    </div>
                </div>

                <p style="color: var(--pv-text-muted); font-size: 13.5px; line-height: 1.6; margin: 0 0 18px 0;">
                    PassVault is an obsidian glassmorphism password manager engineered with zero-knowledge cryptography, ensuring complete sovereignty and privacy over sensitive credentials.
                </p>

                <table class="specs-table" role="presentation">
                    <tbody>
                        <tr>
                            <td>PHP Runtime</td>
                            <td>PHP 8.2+</td>
                        </tr>
                        <tr>
                            <td>Encryption Cipher</td>
                            <td>AES-256-GCM</td>
                        </tr>
                        <tr>
                            <td>Session Storage</td>
                            <td>HttpOnly / SameSite</td>
                        </tr>
                        <tr>
                            <td>CSRF Guard</td>
                            <td>Cryptographic Nonce</td>
                        </tr>
                        <tr>
                            <td>Build Version</td>
                            <td>1.0.0</td>
                        </tr>
                    </tbody>
                </table>
            </section>
        </div>
    </div>
</main>

<!-- Hidden confirmation modal template so vault.js initializes cleanly without null element references -->
<div id="confirmModalBackdrop" class="modal-backdrop" role="dialog" aria-hidden="true" style="display:none;">
    <div class="modal" role="document" aria-modal="true" aria-labelledby="confirmTitle">
        <div class="title" id="confirmTitle">Confirm action</div>
        <div class="desc" id="confirmDesc">Are you sure?</div>
        <div class="controls">
            <button id="modalCancel" class="btn-cancel" type="button">Cancel</button>
            <button id="modalConfirm" class="btn-confirm" type="button">Confirm</button>
        </div>
    </div>
</div>

<script src="../assets/js/vault.js"></script>

</body>
</html>
