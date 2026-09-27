<?php
// dashboard.php - Obsidian Glass Dashboard
require_once '../includes/security.php';
init_secure_session();
require_once '../includes/dbconn.php';

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = intval($_SESSION['user_id']);
$key = get_master_key();

$user_email = $_SESSION['user_email'] ?? '';
$user_name = $user_email !== '' ? explode('@', $user_email)[0] : 'User';

// ---------- Password scoring (php) ----------
function score_password(string $pw): int {
    if ($pw === '') return 0;
    $score = 0;

    // length contribution (up to ~40)
    $score += min(40, strlen($pw) * 3);

    // character variety
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

    return (int)max(0, min(100, round($score)));
}

// ---------- Human friendly time diff ----------
function human_time(string $ts): string {
    try {
        $t = new DateTime($ts);
        $now = new DateTime('now');
        $diff = $now->getTimestamp() - $t->getTimestamp();
        $diff = max(0, $diff);
        if ($diff < 60) return ($diff === 0 ? 'just now' : $diff . 's ago');
        if ($diff < 3600) return round($diff / 60) . 'm ago';
        if ($diff < 86400) return round($diff / 3600) . 'h ago';
        if ($diff < 604800) return round($diff / 86400) . 'd ago';
        return $t->format('M j, Y');
    } catch (Exception $e) {
        return $ts;
    }
}

// ---------- Data functions ----------
function get_vault_stats(mysqli $conn, int $user_id, ?string $key): array {
    $out = [
        'total' => 0,
        'recent_added' => 0,
        'weak' => 0,
        'medium' => 0,
        'strong' => 0,
        'reused' => 0,
        'security_score' => 100,
        'strong_pct' => 0,
        'medium_pct' => 0,
        'weak_pct' => 0,
    ];

    // total credentials
    $stmt = $conn->prepare("SELECT COUNT(*) FROM vault_items WHERE user_id = ?");
    if ($stmt) {
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $stmt->bind_result($out['total']);
        $stmt->fetch();
        $stmt->close();
    }

    // recent_added (last 7 days)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM vault_items WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 7 DAY)");
    if ($stmt) {
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $stmt->bind_result($out['recent_added']);
        $stmt->fetch();
        $stmt->close();
    }

    if ($out['total'] === 0 || empty($key)) {
        return $out;
    }

    // In-memory analysis for strength, reuse, and security score
    // Plaintext passwords are NEVER exposed in the HTML/DOM
    $stmt = $conn->prepare("SELECT password_encrypted FROM vault_items WHERE user_id = ?");
    if ($stmt) {
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $res = $stmt->get_result();

        $weak = 0;
        $medium = 0;
        $strong = 0;
        $scores = [];
        $hashes_count = [];
        $hashes_list = [];

        while ($row = $res->fetch_assoc()) {
            $plain = decrypt_password($row['password_encrypted'] ?? '', $key);
            $s = score_password($plain);
            $scores[] = $s;

            if ($s < 40) {
                $weak++;
            } elseif ($s >= 90) {
                $strong++;
            } else {
                $medium++;
            }

            // Duplicate detection via SHA-256 hash in memory
            $h = hash('sha256', $plain);
            $hashes_list[] = $h;
            $hashes_count[$h] = ($hashes_count[$h] ?? 0) + 1;
        }
        $stmt->close();

        // Calculate duplicate reused occurrences
        $reused = 0;
        foreach ($hashes_list as $h) {
            if (($hashes_count[$h] ?? 0) > 1) {
                $reused++;
            }
        }

        $out['weak'] = $weak;
        $out['medium'] = $medium;
        $out['strong'] = $strong;
        $out['reused'] = $reused;

        $count = count($scores);
        if ($count > 0) {
            $avg_score = array_sum($scores) / $count;
            // Penalty for reused credentials
            $reuse_penalty = ($reused / $count) * 25;
            $final_score = (int)round(max(0, min(100, $avg_score - $reuse_penalty)));
            $out['security_score'] = $final_score;

            // Health distribution percentages
            $out['strong_pct'] = (int)round(($strong / $count) * 100);
            $out['medium_pct'] = (int)round(($medium / $count) * 100);
            $out['weak_pct'] = max(0, 100 - $out['strong_pct'] - $out['medium_pct']);
        }
    }

    return $out;
}

function get_recent_items(mysqli $conn, int $user_id, int $limit = 6): array {
    $rows = [];
    $stmt = $conn->prepare("SELECT id, website, username, created_at, updated_at FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?");
    if ($stmt) {
        $stmt->bind_param('ii', $user_id, $limit);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = $res->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    }
    return $rows;
}

function get_recent_activity(mysqli $conn, int $user_id, int $limit = 6): array {
    $rows = [];
    $stmt = $conn->prepare("SELECT action_type, action_meta, created_at FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?");
    if ($stmt) {
        $stmt->bind_param('ii', $user_id, $limit);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = $res->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    }
    return $rows;
}

// ---------- Fetch Data ----------
$stats = get_vault_stats($conn, $user_id, $key);
$recent = get_recent_items($conn, $user_id, 6);
$activity = get_recent_activity($conn, $user_id, 6);

// Determine security score badge state
$score_tier_class = 'score-ok';
$score_label = 'Optimal';
if ($stats['security_score'] < 50) {
    $score_tier_class = 'score-danger';
    $score_label = 'Critical';
} elseif ($stats['security_score'] < 80) {
    $score_tier_class = 'score-warn';
    $score_label = 'Moderate';
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — PassVault</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../assets/css/theme.css">
  <link rel="stylesheet" href="../assets/css/dashboard.css">
</head>
<body class="dashboard-main">

<div class="mesh" aria-hidden="true"></div>

<?php require_once '../includes/header.php'; ?>

<main class="dashboard-container">

  <!-- 1. Greeting Hero Section -->
  <section class="dashboard-greeting-hero" aria-label="Dashboard Overview">
    <div class="greeting-left">
      <div class="greeting-badge">
        <span class="pulse-dot"></span>
        <span>Encrypted Session Active</span>
      </div>
      <h1 class="greeting-title">
        Welcome back, <span class="user-highlight"><?= htmlspecialchars($user_name) ?></span>
      </h1>
      <p class="greeting-subtitle">
        Your vault protects <strong><?= intval($stats['total']) ?></strong> credentials.
        <strong><?= intval($stats['recent_added']) ?></strong> added in the last 7 days.
      </p>
    </div>

    <div class="greeting-actions" role="toolbar" aria-label="Quick Actions">
      <a href="vault.php#add" class="action-btn action-primary" role="button">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <line x1="12" y1="5" x2="12" y2="19"></line>
          <line x1="5" y1="12" x2="19" y2="12"></line>
        </svg>
        <span>Add Password</span>
      </a>

      <a href="vault.php" class="action-btn action-secondary" role="button">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        <span>Open Vault</span>
      </a>

      <button id="open-generator" class="action-btn action-secondary" type="button">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
        </svg>
        <span>Generate</span>
      </button>
    </div>
  </section>

  <!-- 2. 4 KPI Cards -->
  <section class="dashboard-kpi-grid" aria-label="Key Performance Indicators">
    <!-- Total Credentials -->
    <a href="vault.php" class="kpi-card" title="View all saved credentials in Vault">
      <div class="kpi-header">
        <span class="kpi-title">Total Credentials</span>
        <div class="kpi-icon-badge" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>
      </div>
      <div class="kpi-body">
        <div class="kpi-value"><?= intval($stats['total']) ?></div>
      </div>
      <div class="kpi-footer">
        <span>All saved vault items</span>
        <span class="kpi-link-arrow" aria-hidden="true">&rarr;</span>
      </div>
    </a>

    <!-- Security Score -->
    <a href="vault.php" class="kpi-card kpi-score <?= $score_tier_class ?>" title="Overall Vault Security Health">
      <div class="kpi-header">
        <span class="kpi-title">Security Score</span>
        <div class="kpi-icon-badge" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="m9 12 2 2 4-4"></path>
          </svg>
        </div>
      </div>
      <div class="kpi-body">
        <div class="kpi-value"><?= intval($stats['security_score']) ?>%</div>
      </div>
      <div class="kpi-footer">
        <span><?= htmlspecialchars($score_label) ?> vault strength</span>
        <span class="kpi-link-arrow" aria-hidden="true">&rarr;</span>
      </div>
    </a>

    <!-- Weak Passwords -->
    <a href="vault.php?filter=weak#items" class="kpi-card kpi-weak" title="View passwords requiring attention">
      <div class="kpi-header">
        <span class="kpi-title">Weak Passwords</span>
        <div class="kpi-icon-badge" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </div>
      </div>
      <div class="kpi-body">
        <div class="kpi-value"><?= intval($stats['weak']) ?></div>
      </div>
      <div class="kpi-footer">
        <span>Requires attention (&lt; 40%)</span>
        <span class="kpi-link-arrow" aria-hidden="true">&rarr;</span>
      </div>
    </a>

    <!-- Reused Passwords -->
    <a href="vault.php" class="kpi-card kpi-reused" title="View reused passwords posing stuffing risk">
      <div class="kpi-header">
        <span class="kpi-title">Reused Passwords</span>
        <div class="kpi-icon-badge" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17 1l4 4-4 4"></path>
            <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
            <path d="M7 23l-4-4 4-4"></path>
            <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
          </svg>
        </div>
      </div>
      <div class="kpi-body">
        <div class="kpi-value"><?= intval($stats['reused']) ?></div>
      </div>
      <div class="kpi-footer">
        <span>Credential stuffing risk</span>
        <span class="kpi-link-arrow" aria-hidden="true">&rarr;</span>
      </div>
    </a>
  </section>

  <!-- 3. Password Health Breakdown Card -->
  <section class="health-breakdown-card" aria-label="Password Health Breakdown">
    <div class="health-card-header">
      <div class="health-header-left">
        <h3>Password Health Breakdown</h3>
        <p>Real-time cryptographic strength distribution across all vault credentials</p>
      </div>
      <div class="health-score-pill">
        <span>Overall Vault Score: <?= intval($stats['security_score']) ?>%</span>
      </div>
    </div>

    <!-- Tri-Segment Meter Bar -->
    <div class="health-meter-container" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="<?= intval($stats['security_score']) ?>" aria-label="Strength meter">
      <?php if ($stats['total'] === 0): ?>
        <div class="health-segment seg-empty" style="width: 100%;" title="No passwords stored"></div>
      <?php else: ?>
        <div class="health-segment seg-strong" style="width: <?= intval($stats['strong_pct']) ?>%;" title="Strong: <?= intval($stats['strong']) ?> (<?= intval($stats['strong_pct']) ?>%)"></div>
        <div class="health-segment seg-medium" style="width: <?= intval($stats['medium_pct']) ?>%;" title="Medium: <?= intval($stats['medium']) ?> (<?= intval($stats['medium_pct']) ?>%)"></div>
        <div class="health-segment seg-weak" style="width: <?= intval($stats['weak_pct']) ?>%;" title="Weak: <?= intval($stats['weak']) ?> (<?= intval($stats['weak_pct']) ?>%)"></div>
      <?php endif; ?>
    </div>

    <!-- Interactive Legend Pills -->
    <div class="health-legend-pills">
      <a href="vault.php?filter=strong#items" class="health-pill pill-strong" title="Filter Strong passwords (≥ 90%)">
        <div class="pill-info">
          <span class="pill-dot"></span>
          <span class="pill-label">Strong (≥ 90%)</span>
        </div>
        <div class="pill-stat">
          <?= intval($stats['strong']) ?>
          <span class="pill-pct"><?= intval($stats['strong_pct']) ?>%</span>
        </div>
      </a>

      <a href="vault.php?filter=medium#items" class="health-pill pill-medium" title="Filter Medium passwords (40–89%)">
        <div class="pill-info">
          <span class="pill-dot"></span>
          <span class="pill-label">Medium (40–89%)</span>
        </div>
        <div class="pill-stat">
          <?= intval($stats['medium']) ?>
          <span class="pill-pct"><?= intval($stats['medium_pct']) ?>%</span>
        </div>
      </a>

      <a href="vault.php?filter=weak#items" class="health-pill pill-weak" title="Filter Weak passwords (< 40%)">
        <div class="pill-info">
          <span class="pill-dot"></span>
          <span class="pill-label">Weak (&lt; 40%)</span>
        </div>
        <div class="pill-stat">
          <?= intval($stats['weak']) ?>
          <span class="pill-pct"><?= intval($stats['weak_pct']) ?>%</span>
        </div>
      </a>

      <a href="vault.php" class="health-pill pill-reused" title="Inspect reused passwords in Vault">
        <div class="pill-info">
          <span class="pill-dot"></span>
          <span class="pill-label">Reused Passwords</span>
        </div>
        <div class="pill-stat">
          <?= intval($stats['reused']) ?>
        </div>
      </a>
    </div>
  </section>

  <!-- 4. Split Grid: Recent Credentials & Activity Timeline -->
  <div class="dashboard-split-grid">
    <!-- Left Column: Recent Credentials -->
    <section class="dashboard-card" aria-label="Recent Credentials">
      <div class="dashboard-card-header">
        <div class="card-title-group">
          <h3>Recent Credentials</h3>
          <p>Latest active entries in your vault</p>
        </div>
        <a href="vault.php" class="card-action-link">
          <span>View all in Vault</span>
          <span aria-hidden="true">&rarr;</span>
        </a>
      </div>

      <?php if (empty($recent)): ?>
        <div class="empty-state">
          <div class="empty-icon-wrap" aria-hidden="true">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
          </div>
          <h4>No credentials yet</h4>
          <p>Start securing your digital identity by adding your first vault password.</p>
          <a href="vault.php#add" class="action-btn action-primary">Add Password</a>
        </div>
      <?php else: ?>
        <div class="recent-table-wrap">
          <table class="recent-table">
            <thead>
              <tr>
                <th>Site</th>
                <th>Username</th>
                <th>Updated</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($recent as $row):
                $clean_site = preg_replace('/^https?:\/\/(www\.)?/', '', $row['website'] ?? '');
                $first_char = strtoupper(substr($clean_site, 0, 1)) ?: '🔑';
              ?>
                <tr>
                  <td>
                    <div class="site-badge-group">
                      <div class="site-icon-badge" aria-hidden="true"><?= htmlspecialchars($first_char) ?></div>
                      <span class="site-name-text" title="<?= htmlspecialchars($row['website']) ?>">
                        <?= htmlspecialchars($row['website']) ?>
                      </span>
                    </div>
                  </td>
                  <td>
                    <span class="masked-username" title="<?= htmlspecialchars($row['username'] ?? '') ?>">
                      <?= !empty($row['username']) ? htmlspecialchars($row['username']) : '—' ?>
                    </span>
                  </td>
                  <td>
                    <span class="relative-timestamp"><?= htmlspecialchars(human_time($row['updated_at'])) ?></span>
                  </td>
                  <td>
                    <a href="vault.php" class="table-manage-btn" title="Open entry in vault">
                      <span>Manage</span>
                    </a>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </section>

    <!-- Right Column: Activity Timeline -->
    <section class="dashboard-card" aria-label="Activity Feed">
      <div class="dashboard-card-header">
        <div class="card-title-group">
          <h3>Activity Feed</h3>
          <p>Recent audit events and vault changes</p>
        </div>
      </div>

      <?php if (empty($activity)): ?>
        <div class="empty-activity">
          <p>No recent activity recorded.</p>
        </div>
      <?php else: ?>
        <div class="activity-timeline">
          <?php foreach ($activity as $act):
            $type_raw = strtolower(trim($act['action_type'] ?? ''));
            if (strpos($type_raw, 'add') !== false) {
                $badge_class = 'badge-added';
                $badge_text = 'Added';
            } elseif (strpos($type_raw, 'edit') !== false || strpos($type_raw, 'update') !== false) {
                $badge_class = 'badge-edited';
                $badge_text = 'Edited';
            } elseif (strpos($type_raw, 'del') !== false) {
                $badge_class = 'badge-deleted';
                $badge_text = 'Deleted';
            } else {
                $badge_class = 'badge-default';
                $badge_text = ucfirst($type_raw ?: 'Activity');
            }
          ?>
            <div class="activity-item">
              <div class="activity-indicator <?= $badge_class ?>" aria-hidden="true"></div>
              <div class="activity-inner">
                <div class="activity-top-row">
                  <span class="action-badge <?= $badge_class ?>"><?= htmlspecialchars($badge_text) ?></span>
                  <span class="activity-time"><?= htmlspecialchars(human_time($act['created_at'])) ?></span>
                </div>
                <p class="activity-desc"><?= htmlspecialchars($act['action_meta'] ?? $act['action_type']) ?></p>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </section>
  </div>

  <!-- Dashboard Footer -->
  <footer class="dashboard-footer">
    PassVault &bull; Obsidian Glass Security &bull; <?= date('Y') ?>
  </footer>

</main>

<script>
  document.getElementById('open-generator')?.addEventListener('click', () => {
    window.location.href = 'vault.php#add';
  });
</script>

</body>
</html>
