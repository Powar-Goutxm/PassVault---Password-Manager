<?php
// header.php - Modern PassVault Navigation
require_once __DIR__ . '/security.php';
init_secure_session();

$user_email = isset($_SESSION['user_email']) ? htmlspecialchars($_SESSION['user_email']) : null;
$user_name = $user_email ? htmlspecialchars(explode('@', $user_email)[0]) : '';

// Determine current page for server-side active highlight
$current_page = basename($_SERVER['PHP_SELF']);
$is_dashboard = ($current_page === 'dashboard.php');
$is_vault = ($current_page === 'vault.php');
$is_settings = ($current_page === 'settings.php');
$is_about = ($current_page === 'about.php');
?>

<link rel="stylesheet" href="../assets/css/header.css">

<nav class="modern-clean modern-nav" role="navigation" aria-label="Main Navigation">
  <div class="nav-wrap">

    <!-- BRAND BLOCK -->
    <a href="<?= $user_email ? './dashboard.php' : './index.php' ?>" class="pv-brand" title="PassVault">
      <div class="pv-logo" aria-hidden="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"
             fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <span class="pv-title">PassVault</span>
    </a>

    <!-- CENTER LINKS -->
    <div class="nav-center" id="nav-center-menu">
      <ul class="nav-links">
        <li><a href="./dashboard.php" class="nav-link <?= $is_dashboard ? 'active' : '' ?>" <?= $is_dashboard ? 'aria-current="page"' : '' ?>>Dashboard</a></li>
        <li><a href="./vault.php" class="nav-link <?= $is_vault ? 'active' : '' ?>" <?= $is_vault ? 'aria-current="page"' : '' ?>>Vault</a></li>
        <li><a href="./settings.php" class="nav-link <?= $is_settings ? 'active' : '' ?>" <?= $is_settings ? 'aria-current="page"' : '' ?>>Settings</a></li>
        <li><a href="./about.php" class="nav-link <?= $is_about ? 'active' : '' ?>" <?= $is_about ? 'aria-current="page"' : '' ?>>About</a></li>
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

        <a href="logout.php" class="btn pill ghost" role="button">Logout</a>
      <?php else: ?>
        <a class="nav-link" href="login.php">Log in</a>
        <a class="btn pill primary" href="register.php" role="button">Get Started</a>
      <?php endif; ?>

      <button id="clean-hamburger" class="clean-hamburger" aria-label="Toggle navigation menu" aria-expanded="false" aria-controls="nav-center-menu">
        <span></span><span></span><span></span>
      </button>
    </div>

  </div>
</nav>

<script src="../assets/js/header.js"></script>
