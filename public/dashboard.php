<?php
// dashboard.php
session_start();
require_once '../includes/dbconn.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = intval($_SESSION['user_id']);

// ---------- Encryption helpers (match vault.php) ----------
$keyFile = __DIR__ . '/../private/secret.key';
if (!file_exists($keyFile)) {
    // If no key present, avoid fatal crash; return empty stats instead
    $key = null;
} else {
    $key = file_get_contents($keyFile);
    if ($key === false) $key = null;
    if ($key !== null) {
        if (strlen($key) > 32) $key = substr($key, 0, 32);
        if (strlen($key) < 32) $key = str_pad($key, 32, "\0");
    }
}

function decrypt_password_php(string $b64, ?string $key): string {
    if ($key === null) return '';
    $method = 'AES-256-CBC';
    $raw = base64_decode($b64);
    if ($raw === false) return '';
    $ivlen = openssl_cipher_iv_length($method);
    if (strlen($raw) < $ivlen) return '';
    $iv = substr($raw, 0, $ivlen);
    $ciphertext = substr($raw, $ivlen);
    $plain = openssl_decrypt($ciphertext, $method, $key, OPENSSL_RAW_DATA, $iv);
    return $plain === false ? '' : $plain;
}

// ---------- Password scoring (php) - mirrors client JS logic ----------
function score_password(string $pw): int {
    if ($pw === '') return 0;
    $score = 0;

    // length contribution (up to ~40)
    $score += min(40, strlen($pw) * 3);

    // variety
    if (preg_match('/[a-z]/', $pw)) $score += 10;
    if (preg_match('/[A-Z]/', $pw)) $score += 10;
    if (preg_match('/\d/', $pw)) $score += 12;
    if (preg_match('/[\W_]/', $pw)) $score += 18;

    if (strlen($pw) >= 16) $score += 10;

    // penalty for common sequences
    $common = ['123456','password','123456789','qwerty','111111','12345678','abc123','password1','letmein'];
    $low = strtolower($pw);
    foreach ($common as $c) {
        if (strpos($low, $c) !== false) {
            $score = max(0, $score - 40);
        }
    }

    $score = max(0, min(100, round($score)));
    return (int)$score;
}

// ---------- Human friendly time diff ----------
function human_time(string $ts): string {
    try {
        $t = new DateTime($ts);
        $now = new DateTime('now');
        $diff = $now->getTimestamp() - $t->getTimestamp();
        $diff = max(0, $diff); // Ensure non-negative
        if ($diff < 60) return ($diff == 0 ? 'just now' : $diff . 's ago');
        if ($diff < 3600) return round($diff/60) . 'm ago';
        if ($diff < 86400) return round($diff/3600) . 'h ago';
        if ($diff < 604800) return round($diff/86400) . 'd ago';
        return $t->format('M j, Y');
    } catch (Exception $e) {
        return $ts;
    }
}

// ---------- Data functions ----------
function get_vault_stats(mysqli $conn, int $user_id, ?string $key): array {
    $out = ['total'=>0,'weak'=>0,'strong'=>0,'recent_added'=>0];

    // total
    $stmt = $conn->prepare("SELECT COUNT(*) FROM vault_items WHERE user_id = ?");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $stmt->bind_result($out['total']);
    $stmt->fetch();
    $stmt->close();

    // recent_added (last 7 days)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM vault_items WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 7 DAY)");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $stmt->bind_result($out['recent_added']);
    $stmt->fetch();
    $stmt->close();

    // For weak/strong: if you stored 'strength' column you'd query it.
    // Here, we will fetch passwords (limited to reasonable count) and compute strength.
    // If many rows exist, limit to latest 500 for speed.
    $limit = 500;
    $stmt = $conn->prepare("SELECT password_encrypted FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?");
    $stmt->bind_param('ii', $user_id, $limit);
    $stmt->execute();
    $res = $stmt->get_result();
    $weak = 0;
    $strong = 0;
    while ($row = $res->fetch_assoc()) {
        $plain = decrypt_password_php($row['password_encrypted'] ?? '', $key);
        $s = score_password($plain);
        if ($s < 40) $weak++;
        if ($s >= 90) $strong++;
    }
    $stmt->close();

    $out['weak'] = $weak;
    $out['strong'] = $strong;
    return $out;
}

function get_recent_items(mysqli $conn, int $user_id, int $limit = 6): array {
    $stmt = $conn->prepare("SELECT id, website, username, created_at, updated_at FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?");
    $stmt->bind_param('ii', $user_id, $limit);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = $res->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $rows;
}

function get_recent_activity(mysqli $conn, int $user_id, int $limit = 6): array {
    // If table doesn't exist this will fail gracefully
    $rows = [];
    $q = "SELECT action_type, action_meta, created_at FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?";
    if ($stmt = $conn->prepare($q)) {
        $stmt->bind_param('ii', $user_id, $limit);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = $res->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    }
    return $rows;
}

// ---------- Fetch data ----------
$stats = get_vault_stats($conn, $user_id, $key);
$recent = get_recent_items($conn, $user_id, 6);
$activity = get_recent_activity($conn, $user_id, 6);

// ---------- HTML output ----------
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Dashboard — PassVault</title>
  <link rel="stylesheet" href="../assets/css/style.css">
  <link rel="stylesheet" href="../assets/css/dashboard.css">
  <style>
    /* small overrides for buttons inside table rows to match existing site */
    .action-btn.delete { background: linear-gradient(180deg,#ef4444,#dc2626); color:#fff; border:0; }
  </style>
</head>
<body class="dashboard-main">

<?php require_once '../includes/header.php'; ?>

<div class="container" style="max-width:1200px;margin:0 auto;padding:28px 20px;">

  <!-- Greeting -->
  <section class="greeting-section">
    <div class="greeting-content">
      <h1>Welcome back, <span class="user-name"><?= htmlspecialchars(explode('@', $_SESSION['user_email'])[0]) ?></span></h1>
      <p class="greeting-sub">You have <strong><?= intval($stats['total']) ?></strong> saved passwords. Recently added: <strong><?= intval($stats['recent_added']) ?></strong></p>
    </div>
  </section>

  <!-- Action Tiles -->
  <section class="action-tiles" aria-label="Quick actions">
    <a href="vault.php#add" class="action-tile primary" role="button">
      <div class="tile-icon">➕</div>
      <div class="tile-text">
        <h3>Add password</h3>
        <p>Add a new password to your vault</p>
      </div>
    </a>

    <a href="vault.php" class="action-tile accent" role="button">
      <div class="tile-icon">🔐</div>
      <div class="tile-text">
        <h3>Open vault</h3>
        <p>View and manage all passwords</p>
      </div>
    </a>

    <button id="open-generator" class="action-tile success" type="button">
      <div class="tile-icon">⚡</div>
      <div class="tile-text">
        <h3>Generate</h3>
        <p>Create a strong password quickly</p>
      </div>
    </button>
  </section>

  <!-- Stats -->
  <section class="stats-grid">
    <div class="stat-card">
      <div class="stat-header">
        <h4>Total</h4>
        <div class="stat-badge">🔐</div>
      </div>
      <div class="stat-number"><?= intval($stats['total']) ?></div>
      <div class="stat-meta">All saved entries</div>
    </div>

    <div class="stat-card warning">
      <div class="stat-header">
        <h4>Weak</h4>
        <div class="stat-badge">⚠️</div>
      </div>
      <div class="stat-number"><?= intval($stats['weak']) ?></div>
      <div class="stat-meta">Passwords requiring attention</div>
    </div>

    <div class="stat-card success">
      <div class="stat-header">
        <h4>Strong</h4>
        <div class="stat-badge">✅</div>
      </div>
      <div class="stat-number"><?= intval($stats['strong']) ?></div>
      <div class="stat-meta">Very strong passwords</div>
    </div>

    <div class="stat-card">
      <div class="stat-header">
        <h4>Recent</h4>
        <div class="stat-badge">🕘</div>
      </div>
      <div class="stat-number"><?= count($recent) ?></div>
      <div class="stat-meta">Recently edited/added</div>
    </div>
  </section>

  <!-- Recent Items -->
  <section class="recent-section">
    <div class="section-header">
      <h2>Recent items</h2>
    </div>

    <?php if (empty($recent)): ?>
      <div class="empty-state">
        <div class="empty-icon">🔒</div>
        <h3>No passwords yet</h3>
        <p>Start by adding your first password to secure your accounts.</p>
        <a href="vault.php#add" class="btn">Add password</a>
      </div>
    <?php else: ?>
      <div class="items-table" role="table" aria-label="Recent passwords">
        <div class="table-header" role="row">
          <div>Website</div>
          <div>Username</div>
          <div>Added</div>
        </div>

        <?php foreach ($recent as $row): ?>
          <div class="table-row" role="row">
            <div class="col-website">
              <div class="site-name"><?= htmlspecialchars($row['website']) ?></div>
            </div>
            <div class="col-username">
              <div class="username-masked"><?= htmlspecialchars($row['username']) ?></div>
            </div>
            <div class="col-date">
              <div class="date-text"><?= htmlspecialchars(human_time($row['updated_at'])) ?></div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </section>

  <!-- Activity -->
  <section class="activity-section">
    <div class="section-header">
      <h2>Recent activity</h2>
      <a class="link-text" href="activity.php">See all</a>
    </div>

    <?php if (empty($activity)): ?>
      <div class="empty-activity">No recent activity to show.</div>
    <?php else: ?>
      <div class="activity-feed">
        <?php foreach ($activity as $act): ?>
          <div class="activity-item">
            <div class="activity-icon">🔔</div>
            <div class="activity-content">
              <p class="activity-text"><?= htmlspecialchars($act['action_meta'] ?? $act['action_type']) ?></p>
              <p class="activity-time"><?= htmlspecialchars(human_time($act['created_at'])) ?></p>
            </div>
            <div class="activity-action"><?= htmlspecialchars($act['action_type']) ?></div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </section>

  <footer class="dashboard-footer">
    <div class="footer-content">
      Built with ♥  · <?= date('Y') ?>
    </div>
  </footer>

</div>

<script>
  // hook generator button to open vault generator if present
  document.getElementById('open-generator')?.addEventListener('click', () => {
    // if vault page is available, navigate to it and focus generator
    window.location.href = 'vault.php#add';
  });
</script>

</body>
</html>
