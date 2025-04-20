import streamlit as st
import time
import hashlib
import os 
import json
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# --- data information of user
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # Use a secure random salt in production
LOCKOUT_DURATION = 60 

# --- section login details
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# --- data is loaded
def load_data():
    if os.path.exists(DATA_FILE)    :
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# --- data is saved
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# --- password hashing
def generate_key(password):
    key = pbkdf2_hmac('sha256' , passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()


# --- cryptography.fernet usefor encryption and decryption
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
         cipher = Fernet(generate_key(key))
         return cipher.decrypt(encrypt_text.encode()).decode()
    except Exception as e:
         st.error("Decryption failed. Please check your password.")
         return None

stored_data = load_data()


# --- navigation bar
st.title("🔐 Secure Data Encryption App")
menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Select an option", menu)


# --- home page
if choice == "Home":
    st.subheader("Welcome to the 🔐 Secure Data Encryption App")
# description of app
    st.write("This app allows you to securely store and retrieve sensitive information using encryption.")
    st.write("You can register, log in, and manage your secure data.")
    st.write("All data is encrypted with a password of your choice.")
    st.write("Please choose an option from the sidebar to get started.")
    st.write("🔒 Your data is safe and secure!")
             

# --- Register new user page
elif choice == "Register":
    st.subheader("✏️ Register New User")
    username = st.text_input("Type Username")
    password = st.text_input("Type Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists. Please choose a different name.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                      "data": []
                }
                save_data(stored_data)
                st.success("✅ User Registration successful! You can now log in.")
        else:
            st.warning("⚠️ Please enter both username and password.")
    
    elif choice == "Login":
        st.subheader("🔑 User Login")
        
        if time.time() < st.session_state.lockout_time:
            remaining_time = int(st.session_state.lockout_time - time.time())
            st.warning(f"⏱️ Too many failed attempts. Please wait {remaining_time} seconds.")
            st.stop()

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome, {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid username or password! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.warning(f"⏱️ Too many failed attempts. Locked for 60 seconds.")
                    st.stop()

# --- Store data page
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in first to store data.")
    else:
        st.subheader("💾 Store Secure Data")
        data = st.text_area("Enter your data to encrypt here:")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrprypt and Store"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.warning("⚠️ Both Fields are required to store data.")

# --- Retrieve data page
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please log in first to retrieve data.")
    else:
        st.subheader("🔍 Retrieve Secure Data")
        user_data =  stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found for the user.")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")
            encrypted_input = st.text_area("Enter Encrypted text:")
            passkey = st.text_input("Enter passkey to decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success("✅ Decrypted Data: " + result)
                else:
                    st.error("❌ Decryption failed. Please check your passkey.")