# 🔐 Secure Data Encryption System

This is a **Streamlit-based web app** that allows users to securely **encrypt and store sensitive data** using a unique **passkey**, and later retrieve it with the same passkey. Built as an educational project to demonstrate secure data handling with hashing and encryption.

---

## 🧠 Features

- **Secure Data Storage**: Encrypt and store any text securely.
- **Data Retrieval**: Retrieve encrypted data using a unique passkey.
- **User Authentication**: 
  - Register and log in with a username and password.
  - Lockout mechanism after multiple failed login attempts.
- **Encryption**: AES-level security using `cryptography.fernet`.
- **Smooth Navigation**: Intuitive navigation between pages via the sidebar.
- **Reauthorization Lock**: Lockout after 3 wrong passkey attempts during decryption.

---

## 📦 Technologies Used

- **Python**: Core programming language.
- **[Streamlit](https://streamlit.io/)**: For building the web interface.
- **Cryptography (Fernet)**: For encryption and decryption.
- **Hashlib**: For secure password hashing.
- **Base64**: For encoding keys.

---

## 🚀 How to Run the App

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-folder>