import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import time
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac





STORED_DATA="data.json"  
SALT=b"secure_salt_value"
LOCKOUT_DURATION=60  

if "authenicated_user" not in st.session_state:
    st.session_state.authenicated_user = None
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
    


def load_data():
    if os.path.exists(STORED_DATA):
        with open(STORED_DATA, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(STORED_DATA, 'w') as f:
        json.dump(data, f)
    

def generate_key(passkey):
    key=pbkdf2_hmac('sha256',passkey.encode(),SALT,100000)
    return urlsafe_b64encode(key)




def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256',passkey.encode(),SALT,100000).hex()


def encrypt_data(text,key):
    cipher=Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, key):
    try:
        
        cipher=Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()

    except:
        return None
            
    
stored_data=load_data()




# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home","Register","Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)



if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Reauthorization required.")

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
elif choice == "Register":
    st.subheader("📝 Register a New User")
    username=st.text_input("Choose Username:")
    password=st.text_input("Choose Password:", type="password")
    
    if st.button("Regsiter"):
        if username and password:
            if username in stored_data:
                st.warning("❌ User already exists!")
            else:
                stored_data[username] = {
                    "password": hash_passkey(password),
                    "data":[]
                    }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.warning("⚠️ Both fields are required!") 
            
              

elif choice == "Store Data":
    if not st.session_state.authenicated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                encrypted_text = encrypt_data(user_data,passkey)
                stored_data[st.session_state.authenicated_user]["data"].append(encrypted_text)
                save_data(stored_data)
                st.success("✅ Data stored securely!")
                st.code(encrypted_text)
            else:
                st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    if not st.session_state.authenicated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("🔍 Retrieve Your Data")
        user_data=stored_data.get(st.session_state.authenicated_user, {}).get("data", [])  
        if not user_data:
            st.warning("❌ No data found!")
        else:
            st.write("Your Encrypted Data:")
            for i,item in enumerate(user_data):
                st.write(item,language="text")

            encrypted_text = st.text_input("Enter Encrypted Data:")
            passkey = st.text_input("Enter Passkey:", type="password")
        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                        
            else:
                st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 User Login")
    if time.time() < st.session_state.lockout_time:
        remaining=int(st.session_state.lockout_time - time.time())
        st.error(f"❌ Locked out! Try again in {remaining} seconds.")
        st.stop()
    
    username=st.text_input("Username:")
    password=st.text_input("Password:", type="password")
    
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_passkey(password):
            st.session_state.authenicated_user = username
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")
        else:
            st.session_state.failed_attempts += 1
            remaining_attempts = 3 - st.session_state.failed_attempts
            st.error(f"❌ Incorrect username or password! Attempts remaining: {remaining_attempts}")
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts! Locked out for 60 seconds.")
                st.stop()
                
