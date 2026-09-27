<?php require_once __DIR__ . '/../includes/security.php'; ?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>PassVault — A vault for the passwords you actually use</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="../assets/css/landing.css" />
  </head>
  <body class="landing-body">
    <div class="mesh" aria-hidden="true"></div>
    <?php require __DIR__ . '/../includes/marketing-nav.php'; ?>

    <main>
      <section class="hero">
        <div class="container hero-grid">
          <div>
            <p class="kicker">Password manager · local-first web app</p>
            <h1 class="hero-title">A vault for the passwords you actually use.</h1>
            <p class="hero-sub">
              Store site logins, generate strong secrets, and reveal them only when you need to.
              AES-256-GCM at rest. No fake autofill. No pretend zero-knowledge.
            </p>
            <div class="hero-ctas">
              <a class="btn large primary" href="./register.php">Get Started — It's free</a>
              <a class="btn large ghost" href="./login.php">Log in</a>
            </div>
            <ul class="hero-points">
              <li>AES-256-GCM at rest</li>
              <li>CSPRNG generator</li>
              <li>Reveal on demand</li>
            </ul>
          </div>

          <div class="vault-stage" aria-hidden="true">
            <div class="vault-glow"></div>
            <div class="vault-mock">
              <div class="mock-chrome">
                <span class="mock-dots"><i></i><i></i><i></i></span>
                PassVault
              </div>
              <div class="mock-lock">
                <div>
                  <div class="lock-ring">⌘</div>
                  Unlocking vault
                </div>
              </div>
              <div class="mock-body">
                <div class="mock-search">Search websites…</div>
                <div class="mock-row">
                  <strong>github.com</strong>
                  <span>••••••••k3y</span>
                  <span class="mock-copy">copy</span>
                </div>
                <div class="mock-row">
                  <strong>mail.example</strong>
                  <span>••••••••9xQ</span>
                  <span class="mock-copy">copy</span>
                </div>
                <div class="mock-row">
                  <strong>bank.local</strong>
                  <span>••••••••m2P</span>
                  <span class="mock-copy">copy</span>
                </div>
                <div class="mock-gen">Generated · 20 chars · copied to field</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="section" id="how">
        <div class="container">
          <p class="section-kicker reveal">How it works</p>
          <h2 class="section-title reveal">Three steps. Then you are in the vault.</h2>
          <p class="section-lead reveal">Built as a PHP web app. Create an account, save a row, copy when you need it.</p>
          <div class="steps">
            <article class="glass-card reveal">
              <div class="step-num">01</div>
              <h3>Register</h3>
              <p>Email plus a login password. Sessions are hardened with CSRF tokens and login rate limits.</p>
            </article>
            <article class="glass-card reveal">
              <div class="step-num">02</div>
              <h3>Add an entry</h3>
              <p>Website, username, secret. The secret is encrypted with AES-256-GCM before it is stored.</p>
            </article>
            <article class="glass-card reveal">
              <div class="step-num">03</div>
              <h3>Reveal or copy</h3>
              <p>Ciphertext stays put until you ask. Copy or show a password on demand, then get back to work.</p>
            </article>
          </div>
        </div>
      </section>

      <section class="section" id="features">
        <div class="container">
          <p class="section-kicker reveal">Features</p>
          <h2 class="section-title reveal">What this build actually does</h2>
          <p class="section-lead reveal">Four capabilities that exist in the code — not a 1Password feature list.</p>
          <div class="feature-grid">
            <article class="glass-card feature-card reveal">
              <div class="icon-chip">GCM</div>
              <h3>AES-256-GCM at rest</h3>
              <p>Vault secrets are stored encrypted on the server. This is not zero-knowledge: the app holds a server key.</p>
            </article>
            <article class="glass-card feature-card reveal">
              <div class="icon-chip">RNG</div>
              <h3>Generator</h3>
              <p>Create a long random password in the browser with a CSPRNG, then save or copy it.</p>
            </article>
            <article class="glass-card feature-card reveal">
              <div class="icon-chip">•••</div>
              <h3>Strength meter</h3>
              <p>Live feedback before you save, so weak and reused patterns are harder to ignore.</p>
            </article>
            <article class="glass-card feature-card reveal">
              <div class="icon-chip">eye</div>
              <h3>Reveal on demand</h3>
              <p>Entries stay masked until you copy or show them. No password dump in the first paint.</p>
            </article>
          </div>
        </div>
      </section>

      <section class="section" id="security">
        <div class="container">
          <p class="section-kicker reveal">Security</p>
          <h2 class="section-title reveal">Controls we actually shipped</h2>
          <p class="section-lead reveal">Honest about the threat model. A portfolio vault, not a SOC 2 report.</p>
          <div class="security-grid">
            <article class="glass-card reveal">
              <h3>Encrypted secrets</h3>
              <p>Stored passwords use AES-256-GCM. Login passwords are hashed with PHP’s password_hash.</p>
            </article>
            <article class="glass-card reveal">
              <h3>Session hygiene</h3>
              <p>CSRF tokens on state-changing forms. Session regeneration after login. HttpOnly cookies.</p>
            </article>
            <article class="glass-card reveal">
              <h3>Rate limits</h3>
              <p>Failed logins and reset requests are throttled by IP so stuffing is slower, not impossible.</p>
            </article>
            <article class="glass-card reveal">
              <h3>What we do not claim</h3>
              <p>No browser autofill, no E2E zero-knowledge, no magic multi-device sync product. It is a web vault.</p>
            </article>
          </div>
        </div>
      </section>

      <section class="section" id="stack">
        <div class="container">
          <p class="section-kicker reveal">Built with</p>
          <h2 class="section-title reveal">The stack on GitHub</h2>
          <p class="section-lead reveal">Open source. Inspect the crypto helpers, the vault CRUD, and the schema.</p>
          <div class="built-row reveal">
            <span class="tech-pill">PHP</span>
            <span class="tech-pill">MySQL</span>
            <span class="tech-pill">OpenSSL GCM</span>
            <span class="tech-pill">HTML / CSS / JS</span>
            <span class="tech-pill">Docker Compose</span>
            <a class="tech-pill" href="https://github.com/Powar-Goutxm/PassVault---Password-Manager" rel="noopener noreferrer">GitHub →</a>
          </div>
        </div>
      </section>

      <section class="section">
        <div class="container">
          <div class="glass-card cta-card reveal">
            <h2>Start a vault in a minute</h2>
            <p>Free to register. Open source. Built to show the work, not to impersonate a unicorn.</p>
            <div class="cta-actions">
              <a class="btn large primary" href="./register.php">Create free account</a>
              <a class="btn large ghost" href="./login.php">Log in</a>
            </div>
          </div>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div class="container footer-grid">
        <div>
          <a href="./index.php" class="pv-brand">
            <span class="pv-logo" aria-hidden="true">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            <span>PassVault</span>
          </a>
          <p class="section-lead" style="margin: 14px 0 0">A simple password vault for projects and life — with claims that match the code.</p>
        </div>
        <div>
          <h4>Product</h4>
          <a href="#features">Features</a>
          <a href="#security">Security</a>
          <a href="./about.php">About</a>
        </div>
        <div>
          <h4>Source</h4>
          <a href="https://github.com/Powar-Goutxm/PassVault---Password-Manager" rel="noopener noreferrer">GitHub</a>
          <a href="./login.php">Log in</a>
          <a href="./register.php">Register</a>
        </div>
      </div>
      <div class="container legal">© <span id="site-year"></span> PassVault. Open-source vault.</div>
    </footer>

    <script src="../assets/js/landing.js"></script>
  </body>
</html>
