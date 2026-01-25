<?php
// header.php - Modern PassVault Navigation
if (session_status() === PHP_SESSION_NONE) session_start();
$user_email = isset($_SESSION['user_email']) ? htmlspecialchars($_SESSION['user_email']) : null;
$user_name = $user_email ? htmlspecialchars(explode('@', $user_email)[0]) : '';

// Determine current page for active highlight
$current_page = basename($_SERVER['PHP_SELF']);
$is_dashboard = $current_page === 'dashboard.php';
$is_vault = $current_page === 'vault.php';
$is_settings = $current_page === 'settings.php';
$is_about = $current_page === 'about.php';
?>

<link rel="stylesheet" href="../assets/css/header.css">

<nav class="modern-clean modern-nav" role="navigation" aria-label="Main">
  <div class="nav-wrap">

    <!-- BRAND BLOCK -->
    <a href="./index.php" class="pv-brand" title="Home">
      <div class="pv-logo" aria-hidden="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
             fill="none" stroke="#06b6d4" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <span class="pv-title">PassVault</span>
    </a>

    <!-- CENTER LINKS -->
    <div class="nav-center">
      <ul class="nav-links">
        <li><a href="./dashboard.php" class="nav-link <?= $is_dashboard ? 'active' : '' ?>">Dashboard</a></li>
        <li><a href="./vault.php" class="nav-link <?= $is_vault ? 'active' : '' ?>">Vault</a></li>
        <li><a href="./settings.php" class="nav-link <?= $is_settings ? 'active' : '' ?>">Settings</a></li>
        <li><a href="./about.php" class="nav-link <?= $is_about ? 'active' : '' ?>">About</a></li>
      </ul>
    </div>

    <!-- RIGHT SIDE -->
    <div class="nav-right">
      <?php if ($user_email): ?>
        <div class="user-pill" title="Logged in as <?= $user_email ?>">
          <svg class="user-icon" width="16" height="16" viewBox="0 0 24 24" fill="none">
            <path d="M12 12c2.761 0 5-2.239 5-5s-2.239-5-5-5-5 2.239-5 5 2.239 5 5 5zM3 20c0-3.866 3.134-7 7-7h4c3.866 0 7 3.134 7 7"
                  stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          <span class="user-email"><?= $user_name ?></span>
        </div>

        <a href="logout.php" class="btn pill ghost">Logout</a>
      <?php else: ?>
        <a class="nav-link" href="login.php">Log in</a>
        <a class="btn pill primary" href="register.php">Get Started</a>
      <?php endif; ?>

      <button id="clean-hamburger" class="clean-hamburger" aria-label="Toggle menu" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
    </div>

  </div>
</nav>

<script src="../assets/js/header.js"></script>

