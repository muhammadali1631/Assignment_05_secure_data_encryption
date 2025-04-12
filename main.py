import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

stored_data = {}
failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed = hash_passkey(passkey)
    entry = stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    failed_attempts += 1
    return None

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            stored_data[encrypted] = {"passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill in both fields.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            decrypted = decrypt_data(encrypted_input, passkey)
            if decrypted:
                st.success("✅ Decrypted Data:")
                st.code(decrypted, language="text")
            else:
                attempts_left = 3 - failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please fill in both fields.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "ali1122":
            failed_attempts = 0
            st.success("✅ Logged in! Returning to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
