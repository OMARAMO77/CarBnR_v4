#!/usr/bin/python3
from api.v1.views import app_views
from models.user_keys import User_keys
from models.user import User
from models import storage
from flask import abort, jsonify, make_response, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


# Utility functions
def get_existing_user_keys(user_id):
    """
    Helper function to retrieve existing user_keys for a user.
    """
    user_keys = next((uk for uk in storage.all(User_keys).values() if uk.user_id == user_id), None)
    return user_keys

def validate_user(user_id, role="User"):
    """
    Helper function to validate user existence.
    """
    user = storage.get(User, user_id)
    if not user:
        abort(404, description=f"{role} not found")
    return user

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
    # return base64.b64encode(encrypted_key).decode()
    return encrypted_key

def decrypt_symmetric_key(encrypted_key, private_key):
    # encrypted_key = base64.b64decode(encrypted_key)
    shared_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return shared_key

def encrypt_message(message, shared_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    # return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()
    return ciphertext, iv

def decrypt_message(ciphertext, shared_key, iv):
    """Decrypt a message using AES."""
    # ciphertext = base64.b64decode(ciphertext)
    # iv = base64.b64decode(iv)
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # return plaintext.decode('utf-8')
    return plaintext

# API routes
@app_views.route('/generate-keys/<user_id>', methods=['GET'])
def generate_keys(user_id):
    user = storage.get(User, user_id)
    if not user:
        abort(404, description="User not found")

    if get_existing_user_keys(user.id):
        abort(400, description="User already has keys")

    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Serialize keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create a new User_keys entry
    user_keys_entry = User_keys(
        user_id=user.id,
        private_key=private_key_pem,
        public_key=public_key_pem,
        shared_key=None
    )
    user_keys_entry.save()

    return jsonify({'public_key': public_key_pem.decode()}), 201

@app_views.route('/exchange-key', methods=['POST'])
def exchange_key():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')

    # Validate the presence of sender and recipient in the database
    sender_keys = storage.get(User_keys, sender)
    recipient_keys = storage.get(User_keys, recipient)

    if not sender_keys or not recipient_keys:
        return jsonify({'error': 'Sender or recipient not found'}), 400

    # Generate a random shared symmetric key
    shared_key = os.urandom(32)

    # Retrieve the recipient's public key and encrypt the shared key
    recipient_public_key = serialization.load_pem_public_key(
        recipient_keys.public_key.encode('utf-8'),
        backend=default_backend()
    )
    encrypted_key = encrypt_symmetric_key(shared_key, recipient_public_key)

    # Save the shared key in the sender's database record
    sender_keys.shared_key = shared_key
    storage.save()  # Save changes to the database

    # Return the encrypted shared key
    return jsonify({'encrypted_key': encrypted_key.hex()}), 200

@app_views.route('/send-message', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')

    # Validate sender and recipient presence in the database
    sender_keys = storage.get(User_keys, sender)
    recipient_keys = storage.get(User_keys, recipient)

    if not sender_keys or not recipient_keys:
        return jsonify({'error': 'Sender or recipient not found'}), 400

    # Retrieve the shared key from the sender's database keys
    if not sender_keys.shared_key:
        return jsonify({'error': 'Key exchange not performed'}), 400

    # Convert the shared key (stored as binary in DB) back to bytes
    shared_key = sender_keys.shared_key

    # Encrypt the message using the shared key
    ciphertext, iv = encrypt_message(message, shared_key)

    # Return the encrypted message and initialization vector
    return jsonify({'ciphertext': ciphertext.hex(), 'iv': iv.hex()}), 200

@app_views.route('/store-message', methods=['POST'])
def store_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')
    encrypted_key = data.get('encrypted_key')

    if not (sender and recipient and ciphertext and iv and encrypted_key):
        return jsonify({'error': 'All fields are required'}), 400

    try:
        # Create a new message entry in the database
        new_message = Message(
            sender_id=sender,
            recipient_id=recipient,
            ciphertext=ciphertext,
            iv=iv,
            encrypted_key=encrypted_key
        )
        new_message.save()

        return jsonify({'message': 'Message stored successfully'}), 200

    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app_views.route('/get-message-data', methods=['GET'])
def get_message_data():
    recipient = request.args.get('recipient')
    if not recipient:
        return jsonify({'error': 'Recipient is required'}), 400

    try:
        # Query messages for the recipient using the `Message` model

        user = validate_user(recipient, "Recipient")
        messages = user.messages_received or []

        if not messages:
            return jsonify({'error': 'No message data found for user'}), 404

        # Serialize message data
        message_list = [
            {
                "sender": message.sender_id,
                "ciphertext": message.ciphertext,
                "iv": message.iv,
                "encrypted_key": message.encrypted_key,
                "timestamp": message.created_at.isoformat()
            }
            for message in messages
        ]

        return jsonify({"messages": message_list}), 200

    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app_views.route('/receive-message', methods=['POST'])
def receive_message():
    data = request.json
    recipient = data.get('recipient')
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')
    encrypted_key = data.get('encrypted_key')

    # Validate required fields
    if not all([recipient, ciphertext, iv, encrypted_key]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Fetch the recipient's private key from the database
        user_keys_entry = storage.get(User_keys, recipient)
        # user_keys_entry = User_keys.query.filter_by(user_id=recipient).first()
        if not user_keys_entry:
            return jsonify({'error': 'Recipient not found'}), 400

        private_key_pem = user_keys_entry.private_key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )

        # Decrypt the shared symmetric key
        shared_key = decrypt_symmetric_key(encrypted_key, private_key)

        # Decrypt the message
        plaintext = decrypt_message(ciphertext, shared_key, iv)

        return jsonify({'plaintext': plaintext}), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500
