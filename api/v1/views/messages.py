#!/usr/bin/python3
""" objects that handles all default RestFul API actions for messages """
from models.message import Message
from models.user import User
from models import storage
from api.v1.views import app_views
from flask import abort, jsonify, make_response, request
from flasgger.utils import swag_from


@app_views.route('/users/<user_id>/messages', methods=['GET'],
                 strict_slashes=False)
@swag_from('documentation/message/messages_by_user.yml', methods=['GET'])
def get_messages(user_id):
    """
    Retrieves the list of all messages objects
    of a specific User, or a specific message
    """
    list_messages = []
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    for message in user.messages:
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


@app_views.route('/users/<user_id>/messages', methods=['POST'],
                 strict_slashes=False)
@swag_from('documentation/message/post_message.yml', methods=['POST'])
def post_message(user_id):
    """
    Creates a Message
    """
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    if not request.get_json():
        abort(400, description="Not a JSON")
    if 'name' not in request.get_json():
        abort(400, description="Missing name")

    data = request.get_json()
    instance = Message(**data)
    instance.user_id = user.id
    instance.save()
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

    ignore = ['id', 'user_id', 'created_at', 'updated_at']

    data = request.get_json()
    for key, value in data.items():
        if key not in ignore:
            setattr(message, key, value)
    storage.save()
    return make_response(jsonify(message.to_dict()), 200)
