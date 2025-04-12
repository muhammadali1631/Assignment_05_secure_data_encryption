import streamlit as st
import hashlib
import uuid
from cryptography.fernet import Fernet

def generate_hash(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data_content(content, cipher):
    return cipher.encrypt(content.encode()).decode()

def retrieve_decrypted_data(id, passkey, data_store, cipher):
    if id in data_store:
        entry = data_store[id]
        hashed_key = generate_hash(passkey)
        
        if entry["passkey"] == hashed_key:
            encrypted_content = entry["encrypted_text"]
            return cipher.decrypt(encrypted_content.encode()).decode()
    
    return None

def setup_session_state():
    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = 0
    if 'data_store' not in st.session_state:
        st.session_state.data_store = {}
    if 'current_view' not in st.session_state:
        st.session_state.current_view = "Home"
    if 'cipher' not in st.session_state:
        secret_key = Fernet.generate_key()
        st.session_state.cipher = Fernet(secret_key)

def display_home():
    st.subheader("🏠 Welcome to the Secure Data Storage System")
    st.write("Store and retrieve your sensitive data securely using passkeys.")
    
    st.info("""
    ### How to use this system:
    1. Go to **Store Data** to encrypt and save your information
    2. You’ll get a unique ID for your stored data
    3. Retrieve your data by entering the Data ID and the passkey
    4. After 3 failed attempts, you'll need to log in again
    """)

def display_store_data():
    st.subheader("📂 Store Your Data Securely")
    content = st.text_area("Enter the data you wish to store:")
    passkey = st.text_input("Enter a passkey for encryption:", type="password")

    if st.button("Save & Encrypt Data"):
        if content and passkey:
            data_id = str(uuid.uuid4())
            hashed_key = generate_hash(passkey)
            encrypted_data = encrypt_data_content(content, st.session_state.cipher)
            
            st.session_state.data_store[data_id] = {
                "encrypted_text": encrypted_data, 
                "passkey": hashed_key
            }
            
            st.success("✅ Your data has been securely stored!")
            st.info(f"Your Data ID: **{data_id}**")
            st.warning("⚠️ Please save this Data ID. You'll need it to retrieve your data.")
        else:
            st.error("⚠️ Both fields are required!")

def display_retrieve_data():
    st.subheader("🔍 Retrieve Your Secure Data")
    data_id = st.text_input("Enter your Data ID:")
    passkey = st.text_input("Enter your passkey:", type="password")

    remaining_attempts = 3 - st.session_state.failed_attempts
    st.info(f"Attempts left: {remaining_attempts}")

    if st.button("Decrypt Data"):
        if data_id and passkey:
            if data_id in st.session_state.data_store:
                decrypted_content = retrieve_decrypted_data(
                    data_id, 
                    passkey, 
                    st.session_state.data_store, 
                    st.session_state.cipher
                )

                if decrypted_content:
                    st.success("✅ Data decryption successful!")
                    st.code(decrypted_content, language="text")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many incorrect attempts! Please log in again.")
                        st.session_state.current_view = "Login"
                        st.rerun()  
            else:
                st.error("❌ Data ID not found!")
        else:
            st.error("⚠️ Both fields are required!")

def display_login():
    st.subheader("🔑 Please Reauthorize")
    st.write("You've reached the maximum number of failed attempts. Please log in to continue.")
    master_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # Master password for reauthorization
            st.session_state.failed_attempts = 0
            st.success("✅ Successfully reauthorized! Redirecting to Retrieve Data...")
            st.session_state.current_view = "Retrieve Data"
            st.rerun() 
        else:
            st.error("❌ Incorrect master password!")

def main():
    setup_session_state()
    
    st.title("🔒 Secure Data Encryption System")
    
    pages = ["Home", "Store Data", "Retrieve Data", "Login"]
    selected_page = st.sidebar.selectbox("Navigation", pages, index=pages.index(st.session_state.current_view))
    
    if st.session_state.failed_attempts >= 3 and selected_page != "Login":
        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
        st.session_state.current_view = "Login"
        selected_page = "Login"
    else:
        st.session_state.current_view = selected_page
    
    if selected_page == "Home":
        display_home()
    elif selected_page == "Store Data":
        display_store_data()
    elif selected_page == "Retrieve Data":
        display_retrieve_data()
    elif selected_page == "Login":
        display_login()

if __name__ == "__main__":
    main()
