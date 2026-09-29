# Secure Password Manager

## 1. Project Overview

Secure Password Manager is a web-based password management application developed using Python and Flask. The application allows registered users to securely manage website credentials through a browser-based interface.

The system provides user authentication, encrypted storage of website passwords, password generation, credential management, and security protections against common web application attacks.

---

## 2. Main Features

The application provides the following features:

- User registration
- Secure user login
- Password hashing for account passwords
- Session-based authentication
- Add website credentials
- View saved credentials
- Edit saved credentials
- Delete saved credentials
- Secure random password generation
- Encryption of stored website passwords
- User-specific credential access
- CSRF protection
- Protection against SQL injection through ORM/database queries
- Automatic HTML escaping for XSS protection
- SQLite database storage

---

## 3. Technologies Used

### Programming Language

- Python 3.11

### Web Framework

- Flask

### Database

- SQLite
- Flask-SQLAlchemy

### Security Libraries

- Werkzeug password hashing
- Cryptography / Fernet encryption
- Flask-WTF CSRF protection
- Python `secrets` module

### Frontend

- HTML5
- CSS3
- Jinja2 templates

---

## 4. Project Structure

```text
SecurePasswordManager/
│
├── static/
│   └── style.css
│
├── templates/
│   ├── add_credential.html
│   ├── credentials.html
│   ├── dashboard.html
│   ├── edit_credential.html
│   ├── generate_password.html
│   ├── login.html
│   └── register.html
│
├── app.py
├── requirements.txt
├── setup.bat
├── README.md
└── .gitignore