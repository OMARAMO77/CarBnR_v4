#!/usr/bin/python3
""" objects that handles all default RestFul API actions for messages """
from models.message import Message
from models.user import User
from models import storage
from api.v1.views import app_views
from flask import abort, jsonify, make_response, request
from flasgger.utils import swag_from


@app_views.route('/<recipient_id>/messages_received', methods=['GET'],
                 strict_slashes=False)
@swag_from('documentation/message/messages_by_user.yml', methods=['GET'])
def get_messages_received(recipient_id):
    """
    Retrieves the list of all received message objects
    of a specific User, or a specific message
    """
    list_messages = []
    user = storage.get(User, recipient_id)
    if not user:
        abort(404)
    for message in user.messages_received:
        list_messages.append(message.to_dict())

    return jsonify(list_messages)


@app_views.route('/<sender_id>/messages_sent', methods=['GET'],
                 strict_slashes=False)
@swag_from('documentation/message/messages_by_user.yml', methods=['GET'])
def get_messages_sent(sender_id):
    """
    Retrieves the list of all sent message objects
    of a specific User, or a specific message
    """
    list_messages = []
    user = storage.get(User, sender_id)
    if not user:
        abort(404)
    for message in user.messages_sent:
        list_messages.append(message.to_dict())

    return jsonify(list_messages)


@app_views.route('/messages/<message_id>/', methods=['GET'], strict_slashes=False)
@swag_from('documentation/message/get_message.yml', methods=['GET'])
def get_message(message_id):
    """
    Retrieves a specific message based on id
    """
    message = storage.get(Message, message_id)
    if not message:
        abort(404)
    return jsonify(message.to_dict())


@app_views.route('/messages/<message_id>', methods=['DELETE'], strict_slashes=False)
@swag_from('documentation/message/delete_message.yml', methods=['DELETE'])
def delete_message(message_id):
    """
    Deletes a message based on id provided
    """
    message = storage.get(Message, message_id)

    if not message:
        abort(404)
    storage.delete(message)
    storage.save()

    return make_response(jsonify({}), 200)


@app_views.route('/messages', methods=['POST'], strict_slashes=False)
@swag_from('documentation/message/post_message.yml', methods=['POST'])
def post_message():
    """
    Creates a Message
    """
    # Check if the request body is JSON
    if not request.is_json:
        abort(400, description="Not a JSON")

    data = request.get_json()

    # Validate required fields
    required_fields = ['sender_id', 'recipient_id', 'ciphertext', 'iv', 'encrypted_key']
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        abort(400, description=f"Missing fields: {', '.join(missing_fields)}")

    # Verify sender exists
    sender = storage.get(User, data['sender_id'])
    if not sender:
        abort(404, description="Sender not found")

    # Verify recipient exists
    recipient = storage.get(User, data['recipient_id'])
    if not recipient:
        abort(404, description="Recipient not found")

    # Create and save the message instance
    try:
        instance = Message(**data)
        instance.save()
    except Exception as e:
        abort(500, description=f"Failed to save message: {str(e)}")

    return make_response(jsonify(instance.to_dict()), 201)


@app_views.route('/messages/<message_id>', methods=['PUT'], strict_slashes=False)
@swag_from('documentation/message/put_message.yml', methods=['PUT'])
def put_message(message_id):
    """
    Updates a Message
    """
    message = storage.get(Message, message_id)
    if not message:
        abort(404)

    if not request.get_json():
        abort(400, description="Not a JSON")

    ignore = ['id', 'sender_id', 'recipient_id',
              'created_at', 'updated_at']

    data = request.get_json()
    for key, value in data.items():
        if key not in ignore:
            setattr(message, key, value)
    storage.save()
    return make_response(jsonify(message.to_dict()), 200)
