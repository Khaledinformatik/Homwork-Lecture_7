# Lecture 7
# Implement your login system using sockets.

import socket
import hashlib
import os

# Load password database (username, salt, hashed_password)
PASSWORD_DB = "password_db.txt"


def load_password_db():
    db = {}
    with open(PASSWORD_DB, 'r') as file:
        for line in file:
            username, salt, hashed_password = line.strip().split(',')
            db[username] = (salt, hashed_password)
    return db


def verify_user(username, client_hash, nonce):
    if username not in password_db:
        return False
    salt, stored_hash = password_db[username]
    # Recompute hash using stored salted password and nonce
    recomputed_hash = hashlib.sha256((stored_hash + nonce).encode()).hexdigest()
    return recomputed_hash == client_hash


# Load database
password_db = load_password_db()

# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

print("Server is running...")

while True:
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Step 1: Receive username
    username = conn.recv(1024).decode()

    if username not in password_db:
        conn.send(b"Invalid username")
        conn.close()
        continue

    # Step 2: Send salt and nonce
    salt, _ = password_db[username]
    nonce = os.urandom(16).hex()  # Generate random nonce
    conn.send(f"{salt},{nonce}".encode())

    # Step 3: Receive client's computed hash
    client_hash = conn.recv(1024).decode()

    # Step 4: Verify user
    if verify_user(username, client_hash, nonce):
        conn.send(b"Authentication successful")
    else:
        conn.send(b"Authentication failed")

    conn.close()


# Client Code  :

def compute_hash(password, salt, nonce):
    salted_password = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashlib.sha256((salted_password + nonce).encode()).hexdigest()

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Step 1: Send username
username = input("Enter username: ")
client_socket.send(username.encode())

# Step 2: Receive salt and nonce from server
response = client_socket.recv(1024).decode()

if response == "Invalid username":
    print("Invalid username")
else:
    salt, nonce = response.split(',')

    # Step 3: Compute and send hash
    password = input("Enter password: ")
    client_hash = compute_hash(password, salt, nonce)
    client_socket.send(client_hash.encode())

    # Step 4: Receive authentication result
    result = client_socket.recv(1024).decode()
    print(result)

client_socket.close()
