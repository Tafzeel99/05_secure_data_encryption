# 🔐 Secure Data Encryption System

This is a **Streamlit-based web app** that allows users to securely **encrypt and store sensitive data** using a unique **passkey**, and later retrieve it with the same passkey. Built as an educational project to demonstrate secure data handling with hashing and encryption.

---

## 🧠 Features

- Encrypt and store any text securely
- Retrieve encrypted data using a unique ID and passkey
- Login mechanism after multiple failed attempts
- AES-level security using `cryptography.fernet`
- Smooth navigation between pages via sidebar
- Reauthorization lock after 3 wrong passkey attempts

---

## 📦 Technologies Used

- Python
- [Streamlit](https://streamlit.io/)
- Cryptography (Fernet)
- Hashlib
- Base64

