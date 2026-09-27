<?php
$current = basename($_SERVER['PHP_SELF']);
$is_home = $current === 'index.php';
?>
<header class="site-header">
  <div class="container header-row">
    <a href="./index.php" class="pv-brand">
      <span class="pv-logo" aria-hidden="true">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      </span>
      <span>PassVault</span>
    </a>

    <nav id="landing-nav" class="header-links" aria-label="Marketing">
      <?php if ($is_home): ?>
        <a href="#how">How it works</a>
        <a href="#features">Features</a>
        <a href="#security">Security</a>
        <a href="#stack">Stack</a>
      <?php else: ?>
        <a href="./index.php#features">Features</a>
        <a href="./index.php#security">Security</a>
      <?php endif; ?>
      <a href="./about.php" class="<?= $current === 'about.php' ? 'is-active' : '' ?>">About</a>
    </nav>

    <div class="nav-actions">
      <span class="badge-oss">Open-source vault</span>
      <a class="link-quiet" href="./login.php">Log in</a>
      <a class="btn primary" href="./register.php">Get PassVault</a>
      <button type="button" class="menu-btn" id="landing-menu" aria-label="Menu" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
    </div>
  </div>
</header>
