<?php
// vault.php — Modern PassVault Credential Management
require_once '../includes/security.php';
init_secure_session();
require_once '../includes/dbconn.php';

// Log a user activity
function log_activity(mysqli $conn, int $user_id, string $type, ?string $meta = null): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $stmt = $conn->prepare("INSERT INTO activity_log (user_id, action_type, action_meta, ip) VALUES (?, ?, ?, ?)");
    if ($stmt) {
        $stmt->bind_param('isss', $user_id, $type, $meta, $ip);
        $stmt->execute();
        $stmt->close();
    }
}

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = intval($_SESSION['user_id']);
$csrf_token = generate_csrf_token();
$errors = [];
$messages = [];

$key = get_master_key();
if ($key === null) {
    die("A secure encryption key could not be loaded.");
}

/* ---------- Actions ---------- */
$action = $_POST['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // AJAX Endpoint: On-Demand Password Decryption (SEC-04 Remediation)
    if ($action === "reveal") {
        header('Content-Type: application/json');
        if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
            echo json_encode(['success' => false, 'error' => 'Security token invalid.']);
            exit;
        }

        $id = intval($_POST['id'] ?? 0);
        if ($id <= 0) {
            echo json_encode(['success' => false, 'error' => 'Invalid entry ID.']);
            exit;
        }

        $stmt = $conn->prepare("SELECT password_encrypted FROM vault_items WHERE id = ? AND user_id = ?");
        if ($stmt) {
            $stmt->bind_param("ii", $id, $user_id);
            $stmt->execute();
            $stmt->bind_result($enc);
            if ($stmt->fetch()) {
                $plain = decrypt_password($enc, $key);
                echo json_encode(['success' => true, 'password' => $plain]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Entry not found.']);
            }
            $stmt->close();
        } else {
            echo json_encode(['success' => false, 'error' => 'Database error.']);
        }
        exit;
    }

    // CSRF Check for all state-changing actions (SEC-03 Remediation)
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $errors[] = "Security token mismatch. Please try submitting again.";
    } else {
        if ($action === "add") {
            $website = trim($_POST['website'] ?? '');
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            if ($website === "" || $password === "") {
                $errors[] = "Website and Password are required.";
            } else {
                $enc = encrypt_password($password, $key);
                $sql = $conn->prepare("INSERT INTO vault_items (user_id, website, username, password_encrypted) VALUES (?, ?, ?, ?)");
                if ($sql) {
                    $sql->bind_param("isss", $user_id, $website, $username, $enc);
                    if ($sql->execute()) {
                        $messages[] = "Credential added successfully.";
                        log_activity($conn, $user_id, 'add', "Added item for {$website}");
                    } else {
                        $errors[] = "Failed to add credential.";
                    }
                    $sql->close();
                } else {
                    $errors[] = "Server error.";
                }
            }
        }

        if ($action === "edit") {
            $id = intval($_POST['id'] ?? 0);
            $website = trim($_POST['website'] ?? '');
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            if ($id <= 0 || $website === '') {
                $errors[] = "Invalid input.";
            } else {
                if ($password !== '') {
                    $enc = encrypt_password($password, $key);
                    $sql = $conn->prepare("UPDATE vault_items SET website=?, username=?, password_encrypted=? WHERE id=? AND user_id=?");
                    if ($sql) {
                        $sql->bind_param("sssii", $website, $username, $enc, $id, $user_id);
                    }
                } else {
                    $sql = $conn->prepare("UPDATE vault_items SET website=?, username=? WHERE id=? AND user_id=?");
                    if ($sql) {
                        $sql->bind_param("ssii", $website, $username, $id, $user_id);
                    }
                }
                if (isset($sql) && $sql) {
                    if ($sql->execute()) {
                        $messages[] = "Credential updated successfully.";
                        log_activity($conn, $user_id, 'edit', "Edited item #{$id} ({$website})");
                    } else {
                        $errors[] = "Failed to update credential.";
                    }
                    $sql->close();
                } else {
                    $errors[] = "Server error.";
                }
            }
        }

        if ($action === "delete") {
            $id = intval($_POST['id'] ?? 0);
            if ($id <= 0) {
                $errors[] = "Invalid id.";
            } else {
                $sql = $conn->prepare("DELETE FROM vault_items WHERE id=? AND user_id=?");
                if ($sql) {
                    $sql->bind_param("ii", $id, $user_id);
                    if ($sql->execute()) {
                        $messages[] = "Credential deleted.";
                        log_activity($conn, $user_id, 'delete', "Deleted item #{$id}");
                    } else {
                        $errors[] = "Failed to delete credential.";
                    }
                    $sql->close();
                } else {
                    $errors[] = "Server error.";
                }
            }
        }
    }

    $_SESSION["flash_errors"] = $errors;
    $_SESSION["flash_messages"] = $messages;
    header("Location: vault.php");
    exit;
}

/* ---------- Fetch items ---------- */
$errors = $_SESSION["flash_errors"] ?? [];
$messages = $_SESSION["flash_messages"] ?? [];
unset($_SESSION["flash_errors"], $_SESSION["flash_messages"]);

// Simple server-side password scoring to categorize items
function score_password_php(string $pw): int {
    if ($pw === '') return 0;
    $score = 0;

    $score += min(40, strlen($pw) * 3);
    if (preg_match('/[a-z]/', $pw)) $score += 10;
    if (preg_match('/[A-Z]/', $pw)) $score += 10;
    if (preg_match('/\d/', $pw)) $score += 12;
    if (preg_match('/[^a-zA-Z0-9]/', $pw)) $score += 18;
    if (strlen($pw) >= 16) $score += 10;

    $common = ['123456','password','123456789','qwerty','111111','12345678','abc123','password1','letmein'];
    $low = strtolower($pw);
    foreach ($common as $c) {
        if (strpos($low, $c) !== false) {
            $score = max(0, $score - 40);
            break;
        }
    }

    return (int)max(0, min(100, round($score)));
}

$stmt = $conn->prepare("SELECT id, website, username, password_encrypted, created_at FROM vault_items WHERE user_id=? ORDER BY updated_at DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();

$counts = ['total' => 0, 'weak' => 0, 'medium' => 0, 'strong' => 0];
$items = [];
while ($row = $res->fetch_assoc()) {
    // Decrypt temporarily in memory only to compute security score
    $plain = decrypt_password($row["password_encrypted"], $key);
    $s = score_password_php($plain);
    $row['pw_score'] = $s;
    if ($s < 40) {
        $row['pw_level'] = 'weak';
        $counts['weak']++;
    } elseif ($s >= 90) {
        $row['pw_level'] = 'strong';
        $counts['strong']++;
    } else {
        $row['pw_level'] = 'medium';
        $counts['medium']++;
    }
    // Secure design: Do NOT expose plaintext password in dataset or HTML
    unset($row['password_encrypted']);
    $items[] = $row;
}
$stmt->close();
$counts['total'] = count($items);

// Handle optional filter (weak|medium|strong)
$filter = $_GET['filter'] ?? '';
$allowed = ['weak','medium','strong'];
$active_filter = in_array($filter, $allowed) ? $filter : '';
$display_items = $items;
if ($active_filter !== '') {
    $display_items = array_filter($items, function($a) use ($active_filter) { return ($a['pw_level'] ?? '') === $active_filter; });
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault — PassVault</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/theme.css">
    <link rel="stylesheet" href="../assets/css/header.css">
    <style>
        body.vault-body {
            margin: 0;
            min-height: 100vh;
            background: var(--pv-bg, #07070b);
            color: var(--pv-text, #f1f5f9);
            font-family: var(--pv-font, "Inter", sans-serif);
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        .vault-mesh {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            background:
                radial-gradient(ellipse 70% 50% at 15% 10%, var(--pv-glow-indigo, rgba(99, 102, 241, 0.38)), transparent 58%),
                radial-gradient(ellipse 50% 40% at 90% 85%, var(--pv-glow-cyan, rgba(34, 211, 238, 0.22)), transparent 55%),
                radial-gradient(circle at 50% 50%, #0c0c14 0%, var(--pv-bg, #07070b) 70%);
        }

        .vault-main {
            position: relative;
            z-index: 1;
            max-width: 1200px;
            margin: 0 auto;
            padding: 36px 20px 80px;
        }

        /* Top Header */
        .vault-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }

        .vault-header-kicker {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--pv-cyan, #22d3ee);
            margin: 0 0 6px 0;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .vault-header-title {
            font-family: var(--pv-display, "Outfit", sans-serif);
            font-size: 32px;
            font-weight: 800;
            color: var(--pv-text, #f1f5f9);
            margin: 0 0 6px 0;
            letter-spacing: -0.02em;
        }

        .vault-header-sub {
            color: var(--pv-text-muted, #94a3b8);
            font-size: 15px;
            margin: 0;
        }

        .btn-add-vault {
            background: linear-gradient(135deg, var(--pv-cyan, #22d3ee) 0%, var(--pv-indigo-hot, #818cf8) 100%);
            color: #041016;
            font-family: var(--pv-display, "Outfit", sans-serif);
            font-weight: 700;
            font-size: 14px;
            padding: 12px 20px;
            border-radius: 12px;
            border: none;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 8px 24px rgba(34, 211, 238, 0.25);
            transition: transform 0.2s ease, box-shadow 0.2s ease, filter 0.2s ease;
        }

        .btn-add-vault:hover {
            filter: brightness(1.08);
            transform: translateY(-2px);
            box-shadow: 0 12px 30px rgba(34, 211, 238, 0.35);
        }

        /* Stat cards */
        .stat-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 18px;
            margin-bottom: 32px;
        }

        .stat-card {
            background: var(--pv-glass-strong, rgba(18, 18, 28, 0.72));
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
            border-radius: var(--pv-radius, 16px);
            padding: 22px;
            text-decoration: none;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            backdrop-filter: blur(var(--pv-blur, 12px));
            -webkit-backdrop-filter: blur(var(--pv-blur, 12px));
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
            transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
            cursor: pointer;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            border-color: rgba(34, 211, 238, 0.4);
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
        }

        .stat-card.active {
            border-color: var(--pv-cyan, #22d3ee);
            box-shadow: 0 0 24px rgba(34, 211, 238, 0.2), inset 0 0 12px rgba(34, 211, 238, 0.05);
        }

        .stat-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .stat-card-label {
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            color: var(--pv-text-muted, #94a3b8);
        }

        .stat-card-icon {
            font-size: 18px;
        }

        .stat-card-count {
            font-family: var(--pv-display, "Outfit", sans-serif);
            font-size: 34px;
            font-weight: 800;
            color: var(--pv-text, #f1f5f9);
            margin-bottom: 6px;
            line-height: 1;
        }

        .stat-card.stat-weak .stat-card-count {
            color: var(--pv-danger, #f87171);
        }

        .stat-card.stat-medium .stat-card-count {
            color: #fbbf24;
        }

        .stat-card.stat-strong .stat-card-count {
            color: var(--pv-ok, #34d399);
        }

        .stat-card-desc {
            font-size: 13px;
            color: var(--pv-text-dim, #64748b);
        }

        /* Alerts */
        .alert {
            padding: 14px 18px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
            backdrop-filter: blur(var(--pv-blur, 12px));
            transition: opacity 0.4s ease;
        }

        .alert-success {
            background: rgba(52, 211, 153, 0.1);
            border: 1px solid rgba(52, 211, 153, 0.3);
            color: var(--pv-ok, #34d399);
        }

        .alert-error {
            background: rgba(248, 113, 113, 0.1);
            border: 1px solid rgba(248, 113, 113, 0.3);
            color: var(--pv-danger, #f87171);
        }

        .alert.fade-out {
            opacity: 0;
        }

        /* Controls bar: search and filter pills */
        .vault-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            gap: 16px;
            flex-wrap: wrap;
        }

        .search-box {
            position: relative;
            flex: 1;
            min-width: 280px;
            max-width: 440px;
        }

        .search-box .search-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--pv-text-dim, #64748b);
            pointer-events: none;
        }

        .vault-search-input {
            width: 100%;
            padding: 12px 14px 12px 40px;
            border-radius: 12px;
            border: 1px solid var(--pv-line, rgba(148, 163, 184, 0.12));
            background: var(--pv-glass-strong, rgba(18, 18, 28, 0.72));
            color: var(--pv-text, #f1f5f9);
            font-family: var(--pv-font, "Inter", sans-serif);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
            backdrop-filter: blur(var(--pv-blur, 12px));
        }

        .vault-search-input:focus {
            border-color: var(--pv-cyan, #22d3ee);
            box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.18);
        }

        .filter-pills {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .filter-pill {
            padding: 8px 16px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 600;
            text-decoration: none;
            color: var(--pv-text-muted, #94a3b8);
            background: var(--pv-glass-strong, rgba(18, 18, 28, 0.72));
            border: 1px solid var(--pv-line, rgba(148, 163, 184, 0.12));
            transition: all 0.2s ease;
            backdrop-filter: blur(var(--pv-blur, 12px));
        }

        .filter-pill:hover {
            color: var(--pv-text, #f1f5f9);
            border-color: var(--pv-glass-border, rgba(99, 102, 241, 0.22));
        }

        .filter-pill.active {
            color: var(--pv-cyan, #22d3ee);
            background: rgba(34, 211, 238, 0.1);
            border-color: rgba(34, 211, 238, 0.4);
        }

        /* Credentials Table Card */
        .vault-table-card {
            background: var(--pv-glass-strong, rgba(18, 18, 28, 0.72));
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
            border-radius: var(--pv-radius, 16px);
            backdrop-filter: blur(var(--pv-blur, 12px));
            -webkit-backdrop-filter: blur(var(--pv-blur, 12px));
            box-shadow: var(--pv-shadow, 0 24px 80px rgba(0, 0, 0, 0.45));
            overflow: hidden;
        }

        .table-responsive {
            width: 100%;
            overflow-x: auto;
        }

        table.vault-table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        table.vault-table th {
            padding: 16px 20px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--pv-text-dim, #64748b);
            background: rgba(7, 7, 11, 0.4);
            border-bottom: 1px solid var(--pv-line, rgba(148, 163, 184, 0.12));
        }

        table.vault-table td {
            padding: 16px 20px;
            border-bottom: 1px solid var(--pv-line, rgba(148, 163, 184, 0.12));
            font-size: 14px;
            vertical-align: middle;
        }

        table.vault-table tbody tr {
            transition: background 0.15s ease;
        }

        table.vault-table tbody tr:hover {
            background: rgba(99, 102, 241, 0.04);
        }

        table.vault-table tbody tr:last-child td {
            border-bottom: none;
        }

        .site-cell {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
            color: var(--pv-text, #f1f5f9);
        }

        .site-icon {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: grid;
            place-items: center;
            background: rgba(99, 102, 241, 0.12);
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
            color: var(--pv-cyan, #22d3ee);
            flex-shrink: 0;
            font-size: 14px;
        }

        .username-val {
            color: var(--pv-text-muted, #94a3b8);
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 13px;
        }

        /* Password strength badges */
        .pw-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
        }

        .pw-badge.weak {
            background: rgba(248, 113, 113, 0.12);
            color: var(--pv-danger, #f87171);
            border: 1px solid rgba(248, 113, 113, 0.3);
        }

        .pw-badge.medium {
            background: rgba(251, 191, 36, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(251, 191, 36, 0.3);
        }

        .pw-badge.strong {
            background: rgba(52, 211, 153, 0.12);
            color: var(--pv-ok, #34d399);
            border: 1px solid rgba(52, 211, 153, 0.3);
        }

        .pw-val-box {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            color: var(--pv-text, #f1f5f9);
        }

        .masked {
            letter-spacing: 2px;
            color: var(--pv-text-dim, #64748b);
        }

        .date-val {
            color: var(--pv-text-dim, #64748b);
            font-size: 13px;
        }

        .action-btn-group {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .btn-vault-action {
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            font-family: var(--pv-display, "Outfit", sans-serif);
            cursor: pointer;
            transition: all 0.2s ease;
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
            background: rgba(255, 255, 255, 0.04);
            color: var(--pv-text, #f1f5f9);
        }

        .btn-vault-action:hover {
            filter: brightness(1.15);
            transform: translateY(-1px);
        }

        .btn-vault-action.show-btn:hover {
            border-color: var(--pv-cyan, #22d3ee);
            color: var(--pv-cyan, #22d3ee);
            background: rgba(34, 211, 238, 0.08);
        }

        .btn-vault-action.copy-btn:hover {
            border-color: var(--pv-indigo-hot, #818cf8);
            color: var(--pv-indigo-hot, #818cf8);
            background: rgba(99, 102, 241, 0.08);
        }

        .btn-vault-action.edit-btn:hover {
            border-color: var(--pv-cyan, #22d3ee);
            color: var(--pv-cyan, #22d3ee);
            background: rgba(34, 211, 238, 0.08);
        }

        .btn-vault-action.delete-btn {
            color: var(--pv-danger, #f87171);
            border-color: rgba(248, 113, 113, 0.25);
        }

        .btn-vault-action.delete-btn:hover {
            background: rgba(248, 113, 113, 0.12);
            border-color: var(--pv-danger, #f87171);
        }

        /* Empty state */
        .empty-state {
            padding: 56px 24px;
            text-align: center;
        }

        .empty-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }

        .empty-state h3 {
            font-family: var(--pv-display, "Outfit", sans-serif);
            font-size: 20px;
            font-weight: 700;
            color: var(--pv-text, #f1f5f9);
            margin: 0 0 8px 0;
        }

        .empty-state p {
            color: var(--pv-text-muted, #94a3b8);
            font-size: 14px;
            margin: 0 0 24px 0;
        }

        .no-match-cell {
            padding: 40px !important;
            text-align: center;
            color: var(--pv-text-muted, #94a3b8);
        }

        .no-match-content {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            font-size: 14px;
        }

        /* Accessible Dark Frosted Glass Modals */
        .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.76);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            padding: 20px;
        }

        .modal-backdrop.show {
            display: flex;
        }

        .modal-card {
            background: var(--pv-glass-strong, rgba(18, 18, 28, 0.72));
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
            border-radius: var(--pv-radius, 16px);
            width: 100%;
            max-width: 520px;
            padding: 28px;
            box-shadow: var(--pv-shadow, 0 24px 80px rgba(0, 0, 0, 0.45)), 0 0 0 1px rgba(99, 102, 241, 0.18);
            backdrop-filter: blur(var(--pv-blur, 12px));
            -webkit-backdrop-filter: blur(var(--pv-blur, 12px));
            position: relative;
        }

        .modal-card-sm {
            max-width: 440px;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }

        .modal-title-wrap {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .modal-icon-badge {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: grid;
            place-items: center;
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
            font-size: 16px;
        }

        .modal-icon-badge.danger {
            background: rgba(248, 113, 113, 0.15);
            border-color: rgba(248, 113, 113, 0.3);
        }

        .modal-header h3 {
            font-family: var(--pv-display, "Outfit", sans-serif);
            font-size: 20px;
            font-weight: 700;
            color: var(--pv-text, #f1f5f9);
            margin: 0;
        }

        .modal-close-x {
            background: transparent;
            border: none;
            font-size: 24px;
            color: var(--pv-text-dim, #64748b);
            cursor: pointer;
            padding: 0 4px;
            line-height: 1;
            transition: color 0.2s ease;
        }

        .modal-close-x:hover {
            color: var(--pv-text, #f1f5f9);
        }

        .modal-subtitle {
            font-size: 14px;
            color: var(--pv-text-muted, #94a3b8);
            margin: 0 0 20px 0;
            line-height: 1.5;
        }

        .modal-form {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .form-group label {
            font-size: 13px;
            font-weight: 600;
            color: var(--pv-text, #f1f5f9);
        }

        .form-group .required {
            color: var(--pv-danger, #f87171);
        }

        .form-group .optional {
            color: var(--pv-text-dim, #64748b);
            font-weight: 400;
            font-size: 12px;
        }

        .label-with-action {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .btn-generator-inline {
            background: rgba(34, 211, 238, 0.1);
            border: 1px solid rgba(34, 211, 238, 0.28);
            color: var(--pv-cyan, #22d3ee);
            font-family: var(--pv-font, "Inter", sans-serif);
            font-size: 12px;
            font-weight: 600;
            border-radius: 6px;
            padding: 4px 8px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            transition: all 0.2s ease;
        }

        .btn-generator-inline:hover {
            background: rgba(34, 211, 238, 0.2);
            border-color: var(--pv-cyan, #22d3ee);
            transform: translateY(-1px);
        }

        .input {
            width: 100%;
            padding: 12px 14px;
            border-radius: 10px;
            border: 1px solid var(--pv-line, rgba(148, 163, 184, 0.12));
            background: rgba(7, 7, 11, 0.6);
            color: var(--pv-text, #f1f5f9);
            font-family: var(--pv-font, "Inter", sans-serif);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        .input:focus {
            border-color: var(--pv-cyan, #22d3ee);
            box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.18);
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            margin-top: 10px;
        }

        .btn.pill {
            padding: 10px 18px;
            border-radius: 10px;
            font-family: var(--pv-display, "Outfit", sans-serif);
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            border: none;
            text-decoration: none;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .btn.pill.primary {
            background: linear-gradient(135deg, var(--pv-cyan, #22d3ee) 0%, var(--pv-indigo-hot, #818cf8) 100%);
            color: #041016;
            box-shadow: 0 6px 20px rgba(34, 211, 238, 0.25);
        }

        .btn.pill.primary:hover {
            filter: brightness(1.08);
            transform: translateY(-1px);
        }

        .btn.pill.ghost {
            background: rgba(255, 255, 255, 0.05);
            color: var(--pv-text, #f1f5f9);
            border: 1px solid var(--pv-glass-border, rgba(99, 102, 241, 0.22));
        }

        .btn.pill.ghost:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--pv-line, rgba(148, 163, 184, 0.12));
        }

        .btn.pill.danger {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: #fff;
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.25);
        }

        .btn.pill.danger:hover {
            filter: brightness(1.08);
            transform: translateY(-1px);
        }

        /* Password strength meter in dialogs */
        .pw-strength {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 6px;
        }

        .pw-bar {
            display: flex;
            gap: 6px;
        }

        .pw-bar span {
            width: 32px;
            height: 6px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.08);
            transition: background 0.2s ease;
        }

        .pw-bar span.active-1 {
            background: var(--pv-danger, #f87171);
        }

        .pw-bar span.active-2 {
            background: #fbbf24;
        }

        .pw-bar span.active-3 {
            background: var(--pv-ok, #34d399);
        }

        .pw-bar span.active-4 {
            background: var(--pv-cyan, #22d3ee);
        }

        .pw-label {
            font-size: 12px;
            font-weight: 600;
            color: var(--pv-text-dim, #64748b);
        }

        .pw-label.weak {
            color: var(--pv-danger, #f87171);
        }

        .pw-label.medium {
            color: #fbbf24;
        }

        .pw-label.strong {
            color: var(--pv-ok, #34d399);
        }

        .pw-label.vstrong {
            color: var(--pv-cyan, #22d3ee);
        }

        /* Responsive styling */
        @media (max-width: 900px) {
            .stat-row {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 640px) {
            .stat-row {
                grid-template-columns: 1fr;
            }

            .vault-header {
                flex-direction: column;
                align-items: stretch;
            }

            .btn-add-vault {
                justify-content: center;
            }

            .vault-controls {
                flex-direction: column;
                align-items: stretch;
            }

            .search-box {
                max-width: 100%;
            }

            .action-btn-group {
                flex-wrap: wrap;
            }
        }

        /* Reduced motion compliance */
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }
    </style>
</head>
<body class="vault-body">

<div class="vault-mesh" aria-hidden="true"></div>

<?php require_once '../includes/header.php'; ?>

<main class="vault-main">

    <!-- Global CSRF token for scripts -->
    <input type="hidden" name="csrf_token" id="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

    <!-- Top Header -->
    <header class="vault-header">
        <div class="vault-header-left">
            <div class="vault-header-kicker">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                <span>Encrypted Storage</span>
            </div>
            <h1 class="vault-header-title">Your Vault</h1>
            <p class="vault-header-sub">Securely manage, decrypt, and audit your stored credentials.</p>
        </div>
        <div class="vault-header-right">
            <button type="button" id="openAddModalBtn" class="btn-add-vault">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                <span>+ Add Password</span>
            </button>
        </div>
    </header>

    <!-- Quick stats (click to filter) -->
    <div class="stat-row" role="region" aria-label="Password health breakdown">
        <a href="vault.php" class="stat-card <?= $active_filter === '' ? 'active' : '' ?>" title="All saved passwords">
            <div class="stat-card-header">
                <span class="stat-card-label">TOTAL</span>
                <span class="stat-card-icon">🔐</span>
            </div>
            <div class="stat-card-count"><?= $counts['total'] ?></div>
            <div class="stat-card-desc">All saved entries in vault</div>
        </a>

        <a href="vault.php?filter=weak#items" class="stat-card stat-weak <?= $active_filter === 'weak' ? 'active' : '' ?>" data-filter="weak" title="Weak passwords">
            <div class="stat-card-header">
                <span class="stat-card-label">WEAK</span>
                <span class="stat-card-icon">⚠️</span>
            </div>
            <div class="stat-card-count"><?= $counts['weak'] ?></div>
            <div class="stat-card-desc">Passwords requiring attention</div>
        </a>

        <a href="vault.php?filter=medium#items" class="stat-card stat-medium <?= $active_filter === 'medium' ? 'active' : '' ?>" data-filter="medium" title="Medium passwords">
            <div class="stat-card-header">
                <span class="stat-card-label">MEDIUM</span>
                <span class="stat-card-icon">ℹ️</span>
            </div>
            <div class="stat-card-count"><?= $counts['medium'] ?></div>
            <div class="stat-card-desc">Moderate strength passwords</div>
        </a>

        <a href="vault.php?filter=strong#items" class="stat-card stat-strong <?= $active_filter === 'strong' ? 'active' : '' ?>" data-filter="strong" title="Strong passwords">
            <div class="stat-card-header">
                <span class="stat-card-label">STRONG</span>
                <span class="stat-card-icon">🛡️</span>
            </div>
            <div class="stat-card-count"><?= $counts['strong'] ?></div>
            <div class="stat-card-desc">Very strong passwords</div>
        </a>
    </div>

    <!-- Flash feedback alerts -->
    <?php if (!empty($messages)): ?>
        <div class="alert alert-success" role="alert" aria-live="polite">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <div><?php foreach ($messages as $m) echo htmlspecialchars($m) . " "; ?></div>
        </div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-error" role="alert" aria-live="polite">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <div><?php foreach ($errors as $e) echo htmlspecialchars($e) . " "; ?></div>
        </div>
    <?php endif; ?>

    <!-- Controls: live search & filter pills -->
    <div class="vault-controls">
        <div class="search-box">
            <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input type="text" id="vaultSearch" class="vault-search-input" placeholder="Search by website or username..." aria-label="Search saved passwords">
        </div>
        <div class="filter-pills" role="navigation" aria-label="Filter credentials by strength">
            <a href="vault.php" class="filter-pill <?= $active_filter === '' ? 'active' : '' ?>">All (<?= $counts['total'] ?>)</a>
            <a href="vault.php?filter=weak#items" class="filter-pill <?= $active_filter === 'weak' ? 'active' : '' ?>">Weak (<?= $counts['weak'] ?>)</a>
            <a href="vault.php?filter=medium#items" class="filter-pill <?= $active_filter === 'medium' ? 'active' : '' ?>">Medium (<?= $counts['medium'] ?>)</a>
            <a href="vault.php?filter=strong#items" class="filter-pill <?= $active_filter === 'strong' ? 'active' : '' ?>">Strong (<?= $counts['strong'] ?>)</a>
        </div>
    </div>

    <!-- Credentials Table Section -->
    <section class="vault-table-card" id="items">
        <?php if (empty($display_items)): ?>
            <div class="empty-state">
                <div class="empty-icon">🔐</div>
                <h3>No passwords match this filter</h3>
                <p>No credentials found for the selected category. Add a new credential or reset your filter.</p>
                <button type="button" class="btn pill primary" onclick="document.getElementById('openAddModalBtn').click()">+ Add Password</button>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="vault-table" id="credentialsTable" aria-label="Saved credentials">
                    <thead>
                        <tr>
                            <th>Website</th>
                            <th>Username</th>
                            <th>Strength</th>
                            <th>Password</th>
                            <th>Added</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="vaultTableBody">
                    <?php foreach ($display_items as $it): ?>
                        <tr data-id="<?= $it['id'] ?>" data-website="<?= htmlspecialchars($it['website']) ?>" data-username="<?= htmlspecialchars($it['username']) ?>">
                            <td class="site-col">
                                <div class="site-cell">
                                    <span class="site-icon">🌐</span>
                                    <span class="site-name"><?= htmlspecialchars($it['website']) ?></span>
                                </div>
                            </td>
                            <td class="user-col">
                                <span class="username-val"><?= htmlspecialchars($it['username'] !== '' ? $it['username'] : '—') ?></span>
                            </td>
                            <td class="strength-col">
                                <?php
                                    $lvl = $it['pw_level'] ?? 'medium';
                                    $lbl = ($lvl === 'weak') ? 'Weak' : (($lvl === 'strong') ? 'Strong' : 'Medium');
                                ?>
                                <span class="pw-badge <?= htmlspecialchars($lvl) ?>">
                                    <?= htmlspecialchars($lbl) ?><?php if(isset($it['pw_score'])) echo ' · ' . intval($it['pw_score']) . '%'; ?>
                                </span>
                            </td>
                            <td class="pw-col">
                                <span class="pw-val-box">
                                    <span class="masked">••••••••</span>
                                    <span class="plain" style="display:none"></span>
                                </span>
                            </td>
                            <td class="date-col">
                                <span class="date-val"><?= htmlspecialchars(date('M j, Y', strtotime($it['created_at']))) ?></span>
                            </td>
                            <td class="actions-col">
                                <div class="action-btn-group">
                                    <button type="button" class="btn-vault-action show-btn" title="Reveal password">Show</button>
                                    <button type="button" class="btn-vault-action copy-btn" title="Copy password to clipboard">Copy</button>
                                    <button type="button" class="btn-vault-action edit-btn"
                                            data-id="<?= $it['id'] ?>"
                                            data-website="<?= htmlspecialchars($it['website']) ?>"
                                            data-username="<?= htmlspecialchars($it['username']) ?>"
                                            title="Edit credential">Edit</button>

                                    <form method="post" class="delete-form" style="display:inline">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                                        <input type="hidden" name="id" value="<?= $it['id'] ?>">
                                        <button type="button" class="btn-vault-action delete-btn" data-id="<?= $it['id'] ?>" data-website="<?= htmlspecialchars($it['website']) ?>" title="Delete credential">Delete</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                        <tr id="noSearchMatchRow" style="display:none">
                            <td colspan="6" class="no-match-cell">
                                <div class="no-match-content">
                                    <span>🔍</span>
                                    <span>No credentials match your search query.</span>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

</main>

<!-- Add Modal -->
<div id="addModalBackdrop" class="modal-backdrop" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="addModalTitle">
    <div class="modal-card">
        <div class="modal-header">
            <div class="modal-title-wrap">
                <div class="modal-icon-badge">➕</div>
                <h3 id="addModalTitle">Add Password</h3>
            </div>
            <button type="button" class="modal-close-x modal-cancel-btn" aria-label="Close dialog">&times;</button>
        </div>
        <p class="modal-subtitle">Save a new website credential to your encrypted vault.</p>
        <form method="post" id="addForm" class="modal-form">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

            <div class="form-group">
                <label for="addWebsite">Website URL or Name <span class="required">*</span></label>
                <input class="input" name="website" id="addWebsite" placeholder="https://github.com" required autocomplete="off">
            </div>

            <div class="form-group">
                <label for="addUsername">Username or Email</label>
                <input class="input" name="username" id="addUsername" placeholder="user@example.com" autocomplete="off">
            </div>

            <div class="form-group">
                <div class="label-with-action">
                    <label for="addPassword">Password <span class="required">*</span></label>
                    <button type="button" id="genAddBtn" class="btn-generator-inline" title="Generate strong random password">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                        <span>Generate Strong</span>
                    </button>
                </div>
                <input type="text" class="input password-input" name="password" id="addPassword" placeholder="Enter or generate password" required autocomplete="new-password">
                <div class="pw-strength" data-target="addPassword" aria-hidden="true">
                    <div class="pw-bar"><span></span><span></span><span></span><span></span></div>
                    <div class="pw-label">Strength</div>
                </div>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn pill ghost modal-cancel-btn">Cancel</button>
                <button type="submit" class="btn pill primary">Save Password</button>
            </div>
        </form>
    </div>
</div>

<!-- Edit Modal -->
<div id="editModalBackdrop" class="modal-backdrop" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="editModalTitle">
    <div class="modal-card">
        <div class="modal-header">
            <div class="modal-title-wrap">
                <div class="modal-icon-badge">✏️</div>
                <h3 id="editModalTitle">Edit Password</h3>
            </div>
            <button type="button" class="modal-close-x modal-cancel-btn" aria-label="Close dialog">&times;</button>
        </div>
        <p class="modal-subtitle">Update credential details or set a new encrypted password.</p>
        <form method="post" id="editForm" class="modal-form">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
            <input type="hidden" name="id" id="editEntryId" value="">

            <div class="form-group">
                <label for="editWebsite">Website URL or Name <span class="required">*</span></label>
                <input class="input" name="website" id="editWebsite" required autocomplete="off">
            </div>

            <div class="form-group">
                <label for="editUsername">Username or Email</label>
                <input class="input" name="username" id="editUsername" autocomplete="off">
            </div>

            <div class="form-group">
                <div class="label-with-action">
                    <label for="editPassword">New Password <span class="optional">(leave blank to keep current)</span></label>
                    <button type="button" id="genEditBtn" class="btn-generator-inline" title="Generate strong random password">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                        <span>Generate Strong</span>
                    </button>
                </div>
                <input type="text" class="input password-input" name="password" id="editPassword" placeholder="Leave blank to keep existing password" autocomplete="new-password">
                <div class="pw-strength" data-target="editPassword" aria-hidden="true">
                    <div class="pw-bar"><span></span><span></span><span></span><span></span></div>
                    <div class="pw-label">Strength</div>
                </div>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn pill ghost modal-cancel-btn">Cancel</button>
                <button type="submit" class="btn pill primary">Update Password</button>
            </div>
        </form>
    </div>
</div>

<!-- Confirmation modal (shared for Delete) -->
<div id="confirmModalBackdrop" class="modal-backdrop" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="confirmTitle">
    <div class="modal-card modal-card-sm" role="document">
        <div class="modal-header">
            <div class="modal-title-wrap">
                <div class="modal-icon-badge danger">🗑️</div>
                <h3 id="confirmTitle">Delete Password</h3>
            </div>
            <button type="button" class="modal-close-x modal-cancel-btn" aria-label="Close dialog">&times;</button>
        </div>
        <p class="modal-subtitle" id="confirmDesc">Are you sure you want to permanently delete this saved password? This action cannot be undone.</p>
        <div class="modal-footer">
            <button id="modalCancel" class="btn pill ghost modal-cancel-btn" type="button">Cancel</button>
            <button id="modalConfirm" class="btn pill danger" type="button">Delete</button>
        </div>
    </div>
</div>

<script src="../assets/js/vault.js"></script>

<script>
    // Auto-dismiss alert notifications after 3.5s
    document.addEventListener("DOMContentLoaded", () => {
        const alerts = document.querySelectorAll(".alert");
        if (!alerts.length) return;

        alerts.forEach(alert => {
            setTimeout(() => {
                alert.classList.add("fade-out");
            }, 3500);

            setTimeout(() => {
                alert.style.display = "none";
            }, 4000);
        });
    });

    // Smooth scroll to items table on active filter navigation
    document.addEventListener('DOMContentLoaded', function () {
        const active = <?= json_encode($active_filter) ?>;
        if (!active) return;
        try {
            const target = document.getElementById('items');
            if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (e) {
            // no-op
        }
    });
</script>

</body>
</html>
