<?php
// includes/security.php - Global security, session, and cryptographic utilities

// 1. Send Security Headers (SEC-08 Remediation)
if (!headers_sent()) {
    header("X-Frame-Options: SAMEORIGIN");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline';");
}

// 2. Secure Session Initialization (SEC-06 Remediation)
function init_secure_session(): void {
    if (session_status() === PHP_SESSION_NONE) {
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        ini_set('session.use_strict_mode', '1');
        session_start();
    }
}

// 3. CSRF Protection (SEC-03 Remediation)
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(?string $token): bool {
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

// 4. Rate Limiting Helper (SEC-07 Remediation)
function rate_limit_cache_file(string $ip, string $action = 'login'): string {
    $cacheDir = sys_get_temp_dir() . '/passvault_rate_limits';
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0700, true);
    }
    return $cacheDir . '/' . hash('sha256', $ip . ':' . $action);
}

function check_login_rate_limit(string $ip, int $max = 5, int $decay = 300, string $action = 'login'): array {
    $file = rate_limit_cache_file($ip, $action);
    $now = time();
    $data = ['count' => 0, 'first_attempt' => $now];
    if (file_exists($file)) {
        $content = @file_get_contents($file);
        if ($content) {
            $parsed = @json_decode($content, true);
            if (is_array($parsed) && isset($parsed['first_attempt']) && ($now - $parsed['first_attempt']) < $decay) {
                $data = $parsed;
            }
        }
    }
    if ($data['count'] >= $max) {
        $remaining = $decay - ($now - $data['first_attempt']);
        return [false, max(1, ceil($remaining / 60))];
    }
    return [true, 0];
}

function record_failed_login(string $ip, int $decay = 300, string $action = 'login'): void {
    $file = rate_limit_cache_file($ip, $action);
    $now = time();
    $data = ['count' => 1, 'first_attempt' => $now];
    if (file_exists($file)) {
        $content = @file_get_contents($file);
        if ($content) {
            $parsed = @json_decode($content, true);
            if (is_array($parsed) && isset($parsed['first_attempt']) && ($now - $parsed['first_attempt']) < $decay) {
                $data = $parsed;
                $data['count'] = ($data['count'] ?? 0) + 1;
            }
        }
    }
    @file_put_contents($file, json_encode($data));
}

function clear_failed_logins(string $ip, string $action = 'login'): void {
    $file = rate_limit_cache_file($ip, $action);
    if (file_exists($file)) {
        @unlink($file);
    }
}

function ensure_password_resets_table(mysqli $conn): void {
    $sql = "CREATE TABLE IF NOT EXISTS `password_resets` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `user_id` INT NOT NULL,
        `token_hash` CHAR(64) NOT NULL,
        `expires_at` DATETIME NOT NULL,
        `used_at` DATETIME NULL DEFAULT NULL,
        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX `idx_password_resets_token_hash` (`token_hash`),
        CONSTRAINT `fk_password_resets_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    $conn->query($sql);
}

// 5. Master Key Retrieval
function get_master_key(): ?string {
    // Check if key is provided via Environment Variable (recommended for cloud containers)
    $envKey = getenv('APP_SECRET_KEY') ?: getenv('SECRET_KEY');
    if ($envKey) {
        return (strlen($envKey) === 32) ? $envKey : hash('sha256', $envKey, true);
    }

    $keyFile = __DIR__ . '/../private/secret.key';
    if (!file_exists($keyFile)) {
        $k = random_bytes(32);
        file_put_contents($keyFile, $k);
        @chmod($keyFile, 0600);
    }
    $key = file_get_contents($keyFile);
    if ($key === false || strlen($key) === 0) {
        return null;
    }
    if (strlen($key) === 32) {
        return $key;
    }
    return hash('sha256', $key, true);
}

// 6. Authenticated Cryptography (AES-256-GCM with backward compatibility for AES-256-CBC)
function encrypt_password(string $plain, ?string $key): string {
    if ($key === null || $plain === '') {
        return '';
    }
    $cipher = 'aes-256-gcm';
    $ivlen = openssl_cipher_iv_length($cipher);
    $iv = random_bytes($ivlen);
    $tag = '';
    $ciphertext = openssl_encrypt($plain, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    return 'gcm:' . base64_encode($iv . $tag . $ciphertext);
}

function decrypt_password(string $encoded, ?string $key): string {
    if ($key === null || $encoded === '') {
        return '';
    }

    // Authenticated AES-256-GCM
    if (strpos($encoded, 'gcm:') === 0) {
        $raw = base64_decode(substr($encoded, 4));
        if ($raw === false) return '';
        $cipher = 'aes-256-gcm';
        $ivlen = openssl_cipher_iv_length($cipher);
        if (strlen($raw) < ($ivlen + 16)) return '';
        $iv = substr($raw, 0, $ivlen);
        $tag = substr($raw, $ivlen, 16);
        $ciphertext = substr($raw, $ivlen + 16);
        $plain = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $plain === false ? '' : $plain;
    }

    // Fallback: Legacy AES-256-CBC
    $raw = base64_decode($encoded);
    if ($raw === false) return '';
    $cipher = 'aes-256-cbc';
    $ivlen = openssl_cipher_iv_length($cipher);
    if (strlen($raw) < $ivlen) return '';
    $iv = substr($raw, 0, $ivlen);
    $ciphertext = substr($raw, $ivlen);
    $legacyKey = (strlen($key) > 32) ? substr($key, 0, 32) : str_pad($key, 32, "\0");
    $plain = openssl_decrypt($ciphertext, $cipher, $legacyKey, OPENSSL_RAW_DATA, $iv);
    return $plain === false ? '' : $plain;
}
?>
