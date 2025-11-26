<?php
// vault.php
session_start();
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
$errors = [];
$messages = [];

/* ---------- Key management ---------- */
$keyFile = __DIR__ . '/../private/secret.key';
if (!file_exists($keyFile)) {
    $k = random_bytes(32);
    file_put_contents($keyFile, $k);
    @chmod($keyFile, 0600);
}
$key = file_get_contents($keyFile);
if ($key === false) die("Encryption key missing");

if (strlen($key) > 32) $key = substr($key, 0, 32);
if (strlen($key) < 32) $key = str_pad($key, 32, "\0");

/* ---------- Encrypt / Decrypt (OpenSSL AES-256-CBC) ---------- */
function encrypt_password($plain, $key) {
    $method = "AES-256-CBC";
    $ivlen = openssl_cipher_iv_length($method);
    $iv = random_bytes($ivlen);
    $cipher = openssl_encrypt($plain, $method, $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $cipher);
}

function decrypt_password($encoded, $key) {
    $method = "AES-256-CBC";
    $raw = base64_decode($encoded);
    if (!$raw) return "";
    $ivlen = openssl_cipher_iv_length($method);
    if (strlen($raw) < $ivlen) return "";
    $iv = substr($raw, 0, $ivlen);
    $cipher = substr($raw, $ivlen);
    return openssl_decrypt($cipher, $method, $key, OPENSSL_RAW_DATA, $iv) ?: "";
}

/* ---------- Actions ---------- */
$action = $_POST['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

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
                if ($sql->execute()) {$messages[] = "Item added.";
                log_activity($conn, $user_id, 'add', "Added item for {$website} (username: {$username})");
                }else $errors[] = "Failed to add item.";
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
            if ($sql) {
                if ($sql->execute()) {$messages[] = "Item updated.";
                    log_activity($conn, $user_id, 'edit', "Edited item #{$id} updated website to {$website}");
                }else $errors[] = "Failed to update item.";
                $sql->close();
            } else {
                $errors[] = "Server error.";
            }
        }
    }

    if ($action === "delete") {
        $id = intval($_POST['id'] ?? 0);
        if ($id <= 0) $errors[] = "Invalid id.";
        else {
            $sql = $conn->prepare("DELETE FROM vault_items WHERE id=? AND user_id=?");
            if ($sql) {
                $sql->bind_param("ii", $id, $user_id);
                if ($sql->execute()) {$messages[] = "Item deleted.";
                    log_activity($conn, $user_id, 'delete', "Deleted item #{$id}");
                }else $errors[] = "Failed to delete item.";
                $sql->close();
            } else {
                $errors[] = "Server error.";
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

$stmt = $conn->prepare("SELECT id, website, username, password_encrypted, created_at FROM vault_items WHERE user_id=? ORDER BY updated_at DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();

$items = [];
while ($row = $res->fetch_assoc()) {
    $row["password_plain"] = decrypt_password($row["password_encrypted"], $key);
    $items[] = $row;
}
$stmt->close();

// Simple server-side password scoring to categorize items (keeps logic similar to client-side)
function score_password_php(string $pw): int {
    if ($pw === null || $pw === '') return 0;
    $score = 0;

    // length contribution (up to ~40)
    $score += min(40, strlen($pw) * 3);

    // variety
    if (preg_match('/[a-z]/', $pw)) $score += 10;
    if (preg_match('/[A-Z]/', $pw)) $score += 10;
    if (preg_match('/\d/', $pw)) $score += 12;
    if (preg_match('/[^a-zA-Z0-9]/', $pw)) $score += 18;

    if (strlen($pw) >= 16) $score += 10;

    // common password penalty
    $common = ['123456','password','123456789','qwerty','111111','12345678','abc123','password1','letmein'];
    $low = strtolower($pw);
    foreach ($common as $c) {
        if (strpos($low, $c) !== false) {
            $score = max(0, $score - 40);
            break;
        }
    }

    $score = max(0, min(100, round($score)));
    return (int)$score;
}

// Annotate items with strength and prepare counts
// prepare counts including medium
$counts = ['total' => count($items), 'weak' => 0, 'medium' => 0, 'strong' => 0];
foreach ($items as &$it) {
    $s = score_password_php($it['password_plain'] ?? '');
    $it['pw_score'] = $s;
    if ($s < 40) { $it['pw_level'] = 'weak'; $counts['weak']++; }
    elseif ($s >= 90) { $it['pw_level'] = 'strong'; $counts['strong']++; }
    else { $it['pw_level'] = 'medium'; $counts['medium']++; }
}
unset($it);

// Handle optional filter (weak|strong)
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
    <title>Vault — PassVault</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .stat-row{display:flex;gap:18px;margin:18px 0 26px 0;align-items:stretch}
        .stat-card{flex:1;padding:18px;border-radius:12px;background:linear-gradient(135deg,rgba(6,182,212,0.06),rgba(244,114,182,0.04));cursor:pointer;box-shadow:0 6px 18px rgba(6,182,212,0.03);text-align:center}
        .stat-card h4{margin:0 0 8px 0;font-size:14px;color:#0f172a}
        .stat-card .count{font-size:28px;font-weight:800;color:#0f172a}
        .stat-card.small{background:#fff;border:1px solid rgba(6,182,212,0.06)}
        .stat-card.active{outline:3px solid rgba(6,182,212,0.18);box-shadow:0 10px 28px rgba(6,182,212,0.06)}
        .pw-badge{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:700;font-size:12px}
        .pw-badge.weak{background:linear-gradient(135deg,#ffedd5,#ffefef);color:#b45309;border:1px solid rgba(245,158,11,0.12)}
        .pw-badge.medium{background:linear-gradient(135deg,#eef2ff,#f8fafc);color:#334155;border:1px solid rgba(99,102,241,0.06)}
        .pw-badge.strong{background:linear-gradient(135deg,#dcfce7,#ecfdf5);color:#065f46;border:1px solid rgba(16,185,129,0.08)}
    </style>
</head>
<body>

<?php require_once '../includes/header.php'; ?>


<main class="dashboard-main container">
    <h1>Your Vault</h1>

    <!-- Quick stats (click to filter) -->
    <div class="stat-row" role="region" aria-label="password-stats">
        <a href="vault.php" class="stat-card small <?= $active_filter === '' ? 'active' : '' ?>" title="All passwords">
            <h4>TOTAL</h4>
            <div class="count"><?= $counts['total'] ?></div>
            <div class="muted">All saved entries</div>
        </a>

        <a href="vault.php?filter=weak#items" class="stat-card <?= $active_filter === 'weak' ? 'active' : '' ?>" data-filter="weak" title="Weak passwords">
            <h4>WEAK</h4>
            <div class="count"><?= $counts['weak'] ?></div>
            <div class="muted">Passwords requiring attention</div>
        </a>

        <a href="vault.php?filter=medium#items" class="stat-card <?= $active_filter === 'medium' ? 'active' : '' ?>" data-filter="medium" title="Medium passwords">
            <h4>MEDIUM</h4>
            <div class="count"><?= $counts['medium'] ?></div>
            <div class="muted">Needs review / moderate</div>
        </a>

        <a href="vault.php?filter=strong#items" class="stat-card <?= $active_filter === 'strong' ? 'active' : '' ?>" data-filter="strong" title="Strong passwords">
            <h4>STRONG</h4>
            <div class="count"><?= $counts['strong'] ?></div>
            <div class="muted">Very strong passwords</div>
        </a>
    </div>

    <?php if (!empty($errors)): ?>
        <div class="errors">
            <?php foreach($errors as $e) echo "<div>" . htmlspecialchars($e) . "</div>"; ?>
        </div>
    <?php endif; ?>

   <?php if (!empty($messages)): ?>
    <div class="alert alert-success" aria-live="polite">
        <?php foreach ($messages as $m) echo htmlspecialchars($m); ?>
    </div>
<?php endif; ?>

<?php if (!empty($errors)): ?>
    <div class="alert alert-error" aria-live="polite">
        <?php foreach ($errors as $e) echo htmlspecialchars($e); ?>
    </div>
<?php endif; ?>


    <section class="card" id="items">
        <h3>Saved passwords</h3>

        <?php if (empty($display_items)): ?>
            <p class="small">No items match this filter — add one below or clear filter.</p>
        <?php else: ?>
            <table class="table" aria-live="polite">
                <thead>
                    <tr>
                        <th>Website</th>
                        <th>Username</th>
                        <th>Strength</th>
                        <th>Password</th>
                        <th>Added</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($display_items as $it): ?>
                    <tr>
                        <td><?= htmlspecialchars($it['website']) ?></td>
                        <td><?= htmlspecialchars($it['username']) ?></td>
                        <td>
                            <?php
                                $lvl = $it['pw_level'] ?? 'medium';
                                $lbl = ($lvl === 'weak') ? 'Weak' : (($lvl === 'strong') ? 'Strong' : 'Medium');
                            ?>
                            <span class="pw-badge <?= htmlspecialchars($lvl) ?>"><?= htmlspecialchars($lbl) ?><?php if(isset($it['pw_score'])) echo ' · ' . intval($it['pw_score']) . '%'; ?></span>
                        </td>
                        <td>
                            <span class="masked">•••••••</span>
                            <span class="plain" style="display:none"><?= htmlspecialchars($it['password_plain']) ?></span>
                        </td>
                        <td class="small"><?= htmlspecialchars($it['created_at']) ?></td>
                        <td class="actions">
                            <button type="button" class="btn pill ghost show-btn">Show</button>
                            <button type="button" class="btn pill ghost copy-btn">Copy</button>
                            <button type="button" class="btn pill primary edit-toggle" data-id="<?= $it['id'] ?>">Edit</button>

                            <form method="post" class="delete-form" style="display:inline">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="id" value="<?= $it['id'] ?>">
                                <button type="button" class="btn pill ghost delete-btn" data-id="<?= $it['id'] ?>">Delete</button>
                            </form>
                        </td>
                    </tr>

                    <tr class="edit-row" id="edit-<?= $it['id'] ?>" style="display:none">
                        <td colspan="5">
                            <form method="post">
                                <input type="hidden" name="action" value="edit">
                                <input type="hidden" name="id" value="<?= $it['id'] ?>">
                                <div class="edit-fields" aria-hidden="true">
                                    <input class="input-inline" name="website" value="<?= htmlspecialchars($it['website']) ?>" placeholder="Website">
                                    <input class="input-inline" name="username" value="<?= htmlspecialchars($it['username']) ?>" placeholder="Username">
                                    <input class="input-inline password-input" name="password" placeholder="New password (leave blank to keep)">
                                    <div class="pw-strength" aria-hidden="true">
                                    <div class="pw-bar"><span></span><span></span><span></span><span></span></div>
                                    <div class="pw-label">Strength</div>
                                    </div>

                                    <button type="submit" class="btn pill primary">Save</button>
                                    <button type="button" class="btn pill ghost edit-cancel" data-id="<?= $it['id'] ?>">Cancel</button>
                                </div>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </section>

    <section class="card" style="margin-top:20px;">
        <h3>Add new password</h3>

        <form method="post" id="addForm">
            <input type="hidden" name="action" value="add">
            <div class="add-fields">
                <input class="input-inline" name="website" placeholder="https://example.com" required>
                <input class="input-inline" name="username" placeholder="username / email">
                <input class="input-inline password-input" name="password" id="new-password" placeholder="password" required>
                <div class="pw-strength" data-target="new-password" aria-hidden="true">
                <div class="pw-bar"><span></span><span></span><span></span><span></span></div>
                <div class="pw-label">Strength</div>

                <button type="button" id="genBtn" class="btn pill ghost">Generate</button>
                <button type="submit" class="btn pill primary">Add</button>
            </div>
        </form>
    </section>
</main>

<!-- Confirmation modal (shared) -->
<div id="confirmModalBackdrop" class="modal-backdrop" role="dialog" aria-hidden="true">
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

<script>
  document.addEventListener("DOMContentLoaded", () => {
    const alerts = document.querySelectorAll(".alert");
    if (!alerts.length) return;

    alerts.forEach(alert => {
      setTimeout(() => {
        alert.classList.add("fade-out");
      }, 2000); // wait 2 seconds before fading

      setTimeout(() => {
        alert.style.display = "none";
      }, 2600); // remove from layout after fade
    });
  });
</script>

<script>
    // Smooth-scroll to items if a filter is active and keep focus
    document.addEventListener('DOMContentLoaded', function () {
        const active = <?= json_encode($active_filter) ?>;
        if (!active) return;
        try {
            const target = document.getElementById('items');
            if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            // small visual highlight (already server-set), but ensure class present
            const el = document.querySelector('.stat-card[data-filter="' + active + '"]');
            if (el && !el.classList.contains('active')) el.classList.add('active');
        } catch (e) {
            // no-op on errors
        }
    });
</script>


</body>
</html>
