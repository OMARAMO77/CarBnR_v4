#!/usr/bin/python3
from api.v1.views import app_views
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Store keys for each user (for demonstration purposes)
user_keys = {}
# Extend simulated database
MESSAGES = {}

# Utility functions
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(shared_key, public_key):
    encrypted_key = public_key.encrypt(
        shared_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

def decrypt_symmetric_key(encrypted_key, private_key):
    encrypted_key = base64.b64decode(encrypted_key)
    shared_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return shared_key

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

def decrypt_message(ciphertext, key, iv):
    try:
        decoded_ciphertext = base64.b64decode(ciphertext)
        decoded_iv = base64.b64decode(iv)
        print(f"Decoded Ciphertext: {decoded_ciphertext}")
        print(f"Decoded IV: {decoded_iv}")
    except Exception as e:
        print(f"Base64 decoding failed: {str(e)}")
        raise ValueError("Invalid Base64 encoding")

    try:
        cipher = Cipher(algorithms.AES(key), modes.CFB(decoded_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(decoded_ciphertext) + decryptor.finalize()
        print(f"plaintext: {plaintext}")
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

    # Return the plaintext as-is (binary-safe)
    try:
        return plaintext.decode('utf-8')  # Attempt UTF-8 decoding for text
    except UnicodeDecodeError:
        print("Plaintext is binary data, returning as base64.")
        return base64.b64encode(plaintext).decode('utf-8')  # Return binary data as Base64

# API routes
@app_views.route('/generate-keys/<username>', methods=['GET'])
def generate_keys(username):
    private_key, public_key = generate_rsa_key_pair()
    user_keys[username] = {
        'private_key': private_key,
        'public_key': public_key
    }
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({'public_key': pem.decode()}), 200

@app_views.route('/exchange-key', methods=['POST'])
def exchange_key():
    data = request.json
    username = data['username']
    recipient = data['recipient']
    if username not in user_keys or recipient not in user_keys:
        return jsonify({'error': 'User or recipient not found'}), 400

    shared_key = os.urandom(32)  # Random symmetric key
    recipient_public_key = user_keys[recipient]['public_key']
    encrypted_key = encrypt_symmetric_key(shared_key, recipient_public_key)
    user_keys[username]['shared_key'] = shared_key
    return jsonify({'encrypted_key': encrypted_key}), 200

@app_views.route('/send-message', methods=['POST'])
def send_message():
    data = request.json
    username = data['username']
    recipient = data['recipient']
    message = data['message']
    if username not in user_keys or recipient not in user_keys:
        return jsonify({'error': 'User or recipient not found'}), 400

    shared_key = user_keys[username].get('shared_key')
    if not shared_key:
        return jsonify({'error': 'Key exchange not performed'}), 400

    ciphertext, iv = encrypt_message(message, shared_key)
    return jsonify({'ciphertext': ciphertext, 'iv': iv}), 200

@app_views.route('/store-message', methods=['POST'])
def store_message():
    data = request.json
    username = data.get('username')  # Recipient's username
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')
    encrypted_key = data.get('encrypted_key')

    if not (username and ciphertext and iv and encrypted_key):
        return jsonify({'error': 'All fields are required'}), 400

    # Store the encrypted data for the recipient
    MESSAGES[username] = {
        "ciphertext": ciphertext,
        "iv": iv,
        "encrypted_key": encrypted_key
    }
    return jsonify({'message': 'Message stored successfully'}), 200

@app_views.route('/get-message-data', methods=['GET'])
def get_message_data():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    message_data = MESSAGES.get(username)
    if not message_data:
        return jsonify({'error': 'No message data found for user'}), 404

    return jsonify(message_data)

@app_views.route('/receive-message', methods=['POST'])
def receive_message():
    data = request.json
    username = data['username']
    ciphertext = data['ciphertext']
    iv = data['iv']
    encrypted_key = data['encrypted_key']
    if not all([username, ciphertext, iv, encrypted_key]):
        return jsonify({'error': 'Missing required fields'}), 400

    if username not in user_keys:
        return jsonify({'error': 'User not found'}), 400

    private_key = user_keys[username]['private_key']

    try:
        shared_key = decrypt_symmetric_key(encrypted_key, private_key)
        plaintext = decrypt_message(ciphertext, shared_key, iv)
        return jsonify({'plaintext': plaintext}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500
