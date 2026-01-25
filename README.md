# PassVault 🔐

A simple PHP-based password manager built to understand authentication,
secure data handling, and clean project structure.

> ⚠️ This project is for **learning and demonstration purposes only**.
> Not intended for production use.

---

## ✨ Features

- User authentication (register, login, logout)
- Secure session handling
- Password vault dashboard
- Modular PHP structure using `includes/`
- Separation of sensitive configuration
- Clean UI with CSS & JavaScript assets

---

## 🛠️ Tech Stack

- **Backend:** PHP (mysqli)
- **Frontend:** HTML, CSS, JavaScript
- **Database:** MySQL
- **Server:** Apache (XAMPP)
- **Version Control:** Git & GitHub

---

## 📁 Project Structure

passvault/
├── public/ # Public-facing pages
│ ├── index.php
│ ├── login.php
│ ├── register.php
│ ├── dashboard.php
│ └── vault.php
│
├── includes/ # Shared PHP logic
│ ├── dbconn.php
│ └── header.php
│
├── assets/ # CSS & JS files
│ ├── css/
│ └── js/
│
├── private/ # Sensitive config (ignored)
│ └── dbconfig.php
│
├── sql/ # Database schema
│
├── .gitignore
└── README.md

---

## 🔒 Security Notes

- Database credentials are stored outside the public codebase
- The `private/` directory is ignored using `.gitignore`
- No secrets are committed to the repository

---

## 🚀 Local Setup (XAMPP)

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/PassVault---Password-Manager.git

   ```

2. Move the project into:
   xampp/htdocs/

3. Create a MySQL database named:
   passvault

4. Configure credentials in:
   private/dbconfig.php

5. Start Apache & MySQL in xampp.

6. Open http://localhost/passvault/
