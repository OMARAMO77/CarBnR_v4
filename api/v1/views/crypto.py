#!/usr/bin/python3
from api.v1.views import app_views
from models.user_keys import User_keys
from models.message import Message
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
def validate_user(user_id, role="User"):
    user = storage.get(User, user_id)
    if not user:
        abort(404, description=f"{role} not found")
    return user

def get_existing_user_keys(user_id):
    """
    Helper function to retrieve existing user_keys for a user.
    """
    user_keys = next((uk for uk in storage.all(User_keys).values() if uk.user_id == user_id), None)
    return user_keys

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
    # return encrypted_key

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

def encrypt_message(message, shared_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()
    # return ciphertext, iv

def decrypt_message(ciphertext, shared_key, iv):
    try:
        decoded_ciphertext = base64.b64decode(ciphertext)
        decoded_iv = base64.b64decode(iv)
    except Exception as e:
        print(f"Base64 decoding failed: {str(e)}")
        raise ValueError("Invalid Base64 encoding")

    try:
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(decoded_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(decoded_ciphertext) + decryptor.finalize()
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        print("Plaintext is binary data, returning as base64.")
        return base64.b64encode(plaintext).decode('utf-8')

# API routes
@app_views.route('/generate-keys/<user_id>', methods=['GET'])
def generate_keys(user_id):
    """
    Generate RSA key pair for a user if they don't already have one.
    """
    # Check if user exists in the database
    user = storage.get(User, user_id)
    if not user:
        abort(404, description="User not found")

    # Check if the user already has keys
    existing_keys = get_existing_user_keys(user.id)
    if existing_keys:
        return jsonify({'error': 'User already has keys', 
                        'public_key': existing_keys.public_key.decode()}), 400

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

    return jsonify({'message': 'Keys generated successfully', 
                    'public_key': public_key_pem.decode()}), 201

@app_views.route('/exchange-key', methods=['POST'])
def exchange_key():
    try:
        data = request.json
        sender = data.get('sender')
        recipient = data.get('recipient')

        if not sender or not recipient:
            return jsonify({'error': 'Sender and recipient are required'}), 400

        sender_keys = get_existing_user_keys(sender)
        recipient_keys = get_existing_user_keys(recipient)

        if not sender_keys or not recipient_keys:
            return jsonify({'error': 'Sender or recipient not found'}), 404

        # Generate a random shared symmetric key
        shared_key = os.urandom(32)

        # deserialized public key
        recipient_public_key = serialization.load_pem_public_key(
            recipient_keys.public_key if isinstance(recipient_keys.public_key, bytes) else recipient_keys.public_key.encode('utf-8'),
            backend=default_backend()
        )
        # Encrypt the shared key using the recipient's public key
        encrypted_key = encrypt_symmetric_key(shared_key, recipient_public_key)

        # Save the shared key (binary) in the sender's database record
        sender_keys.shared_key = shared_key  # Store as binary
        storage.save()  # Save changes to the database

        return jsonify({'encrypted_key': encrypted_key}), 200

    except Exception as e:
        print(f"Error in /exchange-key: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


@app_views.route('/send-message', methods=['POST'])
def send_message():
    try:
        data = request.json
        sender = data.get('sender')
        recipient = data.get('recipient')
        message = data.get('message')

        # Validate input
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        if not sender or not recipient:
            return jsonify({'error': 'Sender and recipient are required'}), 400

        # Validate sender and recipient presence in the database
        sender_keys = get_existing_user_keys(sender)
        recipient_keys = get_existing_user_keys(recipient)

        if not sender_keys or not recipient_keys:
            return jsonify({'error': 'Sender or recipient not found'}), 404

        # Retrieve the shared key from the sender's database record
        shared_key = sender_keys.shared_key
        if not shared_key:
            return jsonify({'error': 'Key exchange not performed'}), 400

        # Ensure shared_key is in bytes
        if isinstance(shared_key, str):
            shared_key = bytes.fromhex(shared_key)  # If stored as hex string
        elif not isinstance(shared_key, bytes):
            return jsonify({'error': 'Invalid shared key format'}), 500

        # Encrypt the message using the shared key
        try:
            ciphertext, iv = encrypt_message(message, shared_key)
        except Exception as encryption_error:
            print(f"Encryption error: {encryption_error}")
            return jsonify({'error': 'Encryption failed'}), 500

        # Return the encrypted message and initialization vector
        return jsonify({
            'ciphertext': ciphertext,
            'iv': iv
        }), 200

    except Exception as e:
        print(f"Error in /send-message: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500

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
        # Create and save the message
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
        return jsonify({'error': str(e)}), 500

@app_views.route('/get-message-data', methods=['GET'])
def get_message_data():
    recipient = request.args.get('recipient')
    if not recipient:
        return jsonify({'error': 'Recipient is required'}), 400
    try:
        user = validate_user(recipient, "Recipient")
        
        # Fetch both received and sent messages
        received_messages = user.messages_received or []
        sent_messages = user.messages_sent or []

        # Combine both lists and sort them chronologically
        all_messages = received_messages + sent_messages
        if not all_messages:
            return jsonify({"messages": '', 'error': 'No message data found for recipient'}), 404
        
        # Convert to dict format
        message_list = [message.to_dict() for message in all_messages]
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
        recipient_keys = get_existing_user_keys(recipient)
        if not recipient_keys:
            return jsonify({'error': 'Recipient not found'}), 400

        recipient_private_key = serialization.load_pem_private_key(
            recipient_keys.private_key,  # The serialized private key (byte string)
            password=None,
            backend=default_backend()
        )
        shared_key = decrypt_symmetric_key(encrypted_key, recipient_private_key)
        plaintext = decrypt_message(ciphertext, shared_key, iv)
        return jsonify({'plaintext': plaintext}), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500
