# 🔐 Node.js Authentication with 2-Factor Authentication (2FA)

A secure, production-ready Node.js authentication system featuring:
- JWT-based authentication
- Role-based access control (RBAC)
- Two-Factor Authentication (2FA) via TOTP (Time-based One-Time Password)
- Token refresh system
- Secure password hashing with bcrypt
- Public and protected API routes

> 💡 This project is open-source and designed to showcase secure authentication practices for clients and devs alike.


## 🚀 Features

- ✅ User Registration & Login
- 🔐 Two-Factor Authentication using Google Authenticator (TOTP)
- 🔁 Refresh Token System
- 🛡 Access Control: Admin, Moderator, Member roles
- 🧾 Token Expiry Handling
- 📦 Lightweight setup using NeDB (no external DB needed)
- 🌍 Ready to deploy or integrate into existing projects

---

## 🧰 Tech Stack

- **Node.js + Express**
- **JWT (jsonwebtoken)**
- **bcryptjs**
- **NeDB (file-based DB for lightweight apps)**
- **Speakeasy** – for 2FA (TOTP)
- **QR Code Generator** – for scanning secret with apps like Google Authenticator

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone (https://github.com/alimasoud827/2-Factor-Auth-System.git)
cd 2-Factor-Auth-System
