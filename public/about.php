<?php require_once __DIR__ . '/../includes/security.php'; ?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>About — PassVault</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="../assets/css/landing.css" />
  </head>
  <body class="landing-body about-page">
    <div class="mesh" aria-hidden="true"></div>
    <?php require __DIR__ . '/../includes/marketing-nav.php'; ?>

    <main>
      <section class="hero">
        <div class="container">
          <p class="kicker">About</p>
          <h1 class="hero-title">PassVault is a web vault, not a myth.</h1>
          <p class="hero-sub">
            It is an open-source password manager: accounts, encrypted entries, a generator, and a dashboard.
            Encryption is AES-256-GCM with a server-held key. That is strong storage. It is not end-to-end zero-knowledge.
          </p>
        </div>
      </section>

      <section class="section" style="padding-top: 0">
        <div class="container about-stack">
          <article class="glass-card reveal">
            <h3>What it is</h3>
            <p>
              A PHP + MySQL app where you register, save website credentials, generate passwords, and copy them when needed.
              Activity is logged for your account. Settings cover the basics of the logged-in session.
            </p>
          </article>
          <article class="glass-card reveal">
            <h3>What the crypto does</h3>
            <p>
              Vault secrets are encrypted with AES-256-GCM before they hit the database. Your login password is hashed;
              it is not the vault key. Resetting the login password does not rewrite vault ciphertext.
            </p>
          </article>
          <article class="glass-card reveal">
            <h3>What it is not</h3>
            <p>
              Not a browser extension, not autofill, not a sync client, not a team workspace, and not “we never hold a key.”
              There are no custom tags in this version. Treat it as a portfolio-grade vault you can read on GitHub.
            </p>
          </article>
          <article class="glass-card reveal">
            <h3>Stack</h3>
            <p>PHP, MySQL, HTML/CSS/JS, OpenSSL, optional Docker Compose. v1-style student/open-source project — inspect the repo rather than trust a slogan.</p>
            <div class="built-row" style="margin-top: 16px">
              <span class="tech-pill">PHP</span>
              <span class="tech-pill">MySQL</span>
              <span class="tech-pill">AES-256-GCM</span>
              <span class="tech-pill">CSRF / rate limits</span>
            </div>
          </article>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div class="container footer-grid">
        <div>
          <a href="./index.php" class="pv-brand">PassVault</a>
          <p class="section-lead" style="margin-top: 12px">Open-source vault. Claims match the code.</p>
        </div>
        <div>
          <h4>Product</h4>
          <a href="./index.php#features">Features</a>
          <a href="./index.php#security">Security</a>
        </div>
        <div>
          <h4>Source</h4>
          <a href="https://github.com/Powar-Goutxm/PassVault---Password-Manager" rel="noopener noreferrer">GitHub</a>
        </div>
      </div>
      <div class="container legal">© <span id="site-year"></span> PassVault</div>
    </footer>
    <script src="../assets/js/landing.js"></script>
  </body>
</html>
