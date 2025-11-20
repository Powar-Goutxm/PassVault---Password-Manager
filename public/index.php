<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>PassVault — Modern Password Manager</title>
    <link rel="stylesheet" href="../assets/css/landing.css" />
  </head>
  <body>
    <header class="site-header">
      <div class="container header-row">
        <!-- Consistent global brand -->
        <a href="./dashboard.php" class="pv-brand">
          <div class="pv-logo" aria-hidden="true">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#06b6d4"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span class="pv-title">PassVault</span>
        </a>

        <!-- Right links -->
        <nav class="nav-actions">
          <a href="./login.php" class="link muted">Log in</a>
          <a href="./register.php" class="btn primary">Get PassVault</a>
        </nav>
      </div>
    </header>

    <main>
      <!-- HERO -->
      <section class="hero">
        <div class="container hero-grid">
          <div class="hero-left">
            <h1 class="hero-title">
              Simple. Secure. Fast. Your passwords — Deserve PassVault.
            </h1>
            <p class="hero-sub">
              Store and auto-fill passwords across devices with AES-256
              encryption. Simple UX, serious security.
            </p>

            <div class="hero-ctas">
              <a class="btn large primary" href="./register.php"
                >Get Started — It's free</a
              >
              <a class="btn large ghost" href="./vault.php">Open demo vault</a>
            </div>

            <ul class="hero-features">
              <li>End-to-end encryption</li>
              <li>Generate strong passwords</li>
              <li>Secure cloud sync</li>
            </ul>
          </div>

          <div class="hero-right">
            <div class="device">
              <img src="./img/hero-mock.png" alt="App preview" />
            </div>
          </div>
        </div>
      </section>

      <!-- TRUST -->
      <section class="trust container">
        <p class="trust-title">Trusted by people who care about security</p>

        <div class="trust-logos" role="list">
          <img
            role="listitem"
            src="./img/google.svg"
            alt="Google"
            width="56"
            height="28"
          />
          <img
            role="listitem"
            src="./img/microsoft.svg"
            alt="Microsoft"
            width="56"
            height="28"
          />
          <img
            role="listitem"
            src="./img/slack.svg"
            alt="Slack"
            width="56"
            height="28"
          />
          <img
            role="listitem"
            src="./img/figma.svg"
            alt="Figma"
            width="56"
            height="28"
          />
        </div>
      </section>

      <!-- FEATURES -->
      <section class="container features">
        <h2 class="section-title">Everything you need to protect passwords</h2>

        <div class="feature-grid">
          <article class="feature-card">
            <div class="icon">🔐</div>
            <h3>Zero-knowledge encryption</h3>
            <p>
              Only you hold the key — all entries encrypted locally before
              storage.
            </p>
          </article>

          <article class="feature-card">
            <div class="icon">⚡</div>
            <h3>Autofill & auto-login</h3>
            <p>
              Log in faster with one click and keep unique passwords for every
              site.
            </p>
          </article>

          <article class="feature-card">
            <div class="icon">🧩</div>
            <h3>Password generator</h3>
            <p>Create long randomized passwords — copy or save instantly.</p>
          </article>

          <article class="feature-card">
            <div class="icon">🔁</div>
            <h3>Sync across devices</h3>
            <p>
              Optional secure sync so you can access passwords on any device.
            </p>
          </article>
        </div>
      </section>

      <!-- CTA -->
      <section class="container cta">
        <div class="cta-card">
          <h3>Start securing your accounts today</h3>
          <div>
            <a class="btn primary" href="./register.php">Create free account</a>
            <a class="btn ghost" href="./vault.php">Try demo</a>
          </div>
        </div>
      </section>

      <!-- FOOTER -->
      <footer class="site-footer">
        <div class="container footer-grid">
          <div>
            <div class="pv-brand pv-footer">
              <div class="pv-logo small">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#06b6d4"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <span class="pv-title footer-title">PassVault</span>
            </div>

            <p class="muted">
              PassVault — simple password manager for your projects and life.
            </p>
          </div>

          <div class="links">
            <h4>Product</h4>
            <a href="#">Features</a>
            <a href="#">Pricing</a>
            <a href="#">Security</a>
          </div>

          <div class="links">
            <h4>Company</h4>
            <a href="#">About</a>
            <a href="#">Careers</a>
            <a href="#">Contact</a>
          </div>

          <div class="links">
            <h4>Follow</h4>
            <a href="#">Twitter</a>
            <a href="#">GitHub</a>
          </div>
        </div>

        <div class="container small muted" style="padding: 18px 20px">
          © <span id="site-year"></span> PassVault..
        </div>
      </footer>
    </main>

    <script>
      document.getElementById("site-year").textContent =
        new Date().getFullYear();
    </script>
  </body>
</html>
