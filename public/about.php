<?php
session_start();
if (!isset($_SESSION['user_email'])) {
    header("Location: ./login.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About - PassVault</title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <link rel="stylesheet" href="../assets/css/dashboard.css">
    <style>
        body {
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.08) 0%, rgba(244, 114, 182, 0.06) 100%);
            min-height: 100vh;
        }

        .about-container {
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }

        .about-header {
            text-align: center;
            margin-bottom: 60px;
        }

        .about-header h1 {
            font-size: 36px;
            color: #0f172a;
            margin-bottom: 12px;
            background: linear-gradient(135deg, #06b6d4, #f472b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .about-header p {
            font-size: 18px;
            color: #64748b;
            line-height: 1.6;
        }

        .about-section {
            background: white;
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
            border: 1px solid rgba(6, 182, 212, 0.1);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
        }

        .about-section h2 {
            font-size: 24px;
            color: #0f172a;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .about-section p {
            color: #475569;
            line-height: 1.8;
            margin-bottom: 12px;
            font-size: 15px;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .feature-card {
            padding: 20px;
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.05), rgba(244, 114, 182, 0.03));
            border-radius: 12px;
            border: 1px solid rgba(6, 182, 212, 0.1);
        }

        .feature-card h3 {
            font-size: 16px;
            color: #06b6d4;
            margin-bottom: 8px;
            font-weight: 700;
        }

        .feature-card p {
            font-size: 14px;
            color: #64748b;
            margin: 0;
        }

        .tech-stack {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 16px;
        }

        .tech-badge {
            display: inline-block;
            padding: 8px 14px;
            background: linear-gradient(135deg, #06b6d4, #0891b2);
            color: white;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }

        .version-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: rgba(6, 182, 212, 0.05);
            border-radius: 12px;
            margin-top: 16px;
        }

        .version-info span {
            font-weight: 600;
            color: #0f172a;
        }

        .version-badge {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            padding: 6px 12px;
            border-radius: 16px;
            font-size: 12px;
            font-weight: 700;
        }

        @media (max-width: 768px) {
            .about-container {
                margin: 20px auto;
            }

            .about-header h1 {
                font-size: 28px;
            }

            .about-section {
                padding: 20px;
            }

            .features-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <?php require_once '../includes/header.php'; ?>

    <div class="about-container">
        <div class="about-header">
            <h1>About PassVault</h1>
            <p>A modern, secure, and user-friendly password manager built for your privacy.</p>
        </div>

        <div class="about-section">
            <h2>🔒 What is PassVault?</h2>
            <p>PassVault is a next-generation password manager designed to help you manage all your passwords securely in one place. With end-to-end encryption and a beautiful, intuitive interface, PassVault makes password management effortless.</p>
            <p>Whether you're managing personal accounts or team credentials, PassVault provides the security and convenience you need without compromising on privacy.</p>
        </div>

        <div class="about-section">
            <h2>✨ Key Features</h2>
            <div class="features-grid">
                <div class="feature-card">
                    <h3>🔐 Military-Grade Encryption</h3>
                    <p>Your passwords are encrypted using AES-256, the same encryption standard used by governments worldwide.</p>
                </div>
                <div class="feature-card">
                    <h3>⚡ Lightning Fast</h3>
                    <p>Instant access to your passwords with zero lag. Optimized for speed and performance.</p>
                </div>
                <div class="feature-card">
                    <h3>📱 Beautiful Design</h3>
                    <p>Modern, clean interface that's easy to use. Designed with user experience in mind.</p>
                </div>
                <div class="feature-card">
                    <h3>🔍 Password Strength Analyzer</h3>
                    <p>Get instant feedback on password strength and security recommendations.</p>
                </div>
                <div class="feature-card">
                    <h3>🎯 Smart Organization</h3>
                    <p>Organize your passwords with custom tags and easy-to-use search functionality.</p>
                </div>
                <div class="feature-card">
                    <h3>🛡️ Your Privacy Matters</h3>
                    <p>We never store your master password. Your data stays completely private.</p>
                </div>
            </div>
        </div>

        <div class="about-section">
            <h2>🛠️ Technology Stack</h2>
            <p>PassVault is built with modern, reliable technologies:</p>
            <div class="tech-stack">
                <span class="tech-badge">PHP 7.4+</span>
                <span class="tech-badge">MySQL 5.7+</span>
                <span class="tech-badge">HTML5</span>
                <span class="tech-badge">CSS3</span>
                <span class="tech-badge">JavaScript</span>
                <span class="tech-badge">AES-256 Encryption</span>
            </div>
        </div>

        <div class="about-section">
            <h2>📊 Version & Status</h2>
            <div class="version-info">
                <span>PassVault Version</span>
                <span class="version-badge">v1.0.0</span>
            </div>
            <p style="margin-top: 16px; font-size: 14px; color: #64748b;">
                <strong>Status:</strong> Actively maintained and regularly updated with new features and security improvements.
            </p>
        </div>

        <div class="about-section">
            <h2>❓ Questions?</h2>
            <p>Need help or have feedback? Visit our <strong>Settings</strong> page to manage your account or check out the <strong>Help</strong> section in the main menu.</p>
            <p style="margin-top: 16px; font-size: 13px; color: #94a3b8;">
                PassVault © 2025. All rights reserved. Built with ❤️ for security-conscious users.
            </p>
        </div>
    </div>
</body>
</html>
