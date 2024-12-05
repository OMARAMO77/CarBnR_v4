#!/usr/bin/python3
""" objects that handles all default RestFul API actions for user_keyss """
from models.user_keys import User_keys
from models.user import User
from models import storage
from api.v1.views import app_views
from flask import abort, jsonify, make_response, request
from flasgger.utils import swag_from


@app_views.route('/users/<user_id>/user_keyss', methods=['GET'],
                 strict_slashes=False)
@swag_from('documentation/user_keys/user_keyss_by_user.yml', methods=['GET'])
def get_user_keyss(user_id):
    """
    Retrieves the list of all user_keyss objects
    of a specific User, or a specific user_keys
    """
    list_user_keyss = []
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    for user_keys in user.user_keyss:
        list_user_keyss.append(user_keys.to_dict())

    return jsonify(list_user_keyss)


@app_views.route('/user_keyss/<user_keys_id>/', methods=['GET'], strict_slashes=False)
@swag_from('documentation/user_keys/get_user_keys.yml', methods=['GET'])
def get_user_keys(user_keys_id):
    """
    Retrieves a specific user_keys based on id
    """
    user_keys = storage.get(User_keys, user_keys_id)
    if not user_keys:
        abort(404)
    return jsonify(user_keys.to_dict())


@app_views.route('/user_keyss/<user_keys_id>', methods=['DELETE'], strict_slashes=False)
@swag_from('documentation/user_keys/delete_user_keys.yml', methods=['DELETE'])
def delete_user_keys(user_keys_id):
    """
    Deletes a user_keys based on id provided
    """
    user_keys = storage.get(User_keys, user_keys_id)

    if not user_keys:
        abort(404)
    storage.delete(user_keys)
    storage.save()

    return make_response(jsonify({}), 200)


@app_views.route('/users/<user_id>/user_keyss', methods=['POST'],
                 strict_slashes=False)
@swag_from('documentation/user_keys/post_user_keys.yml', methods=['POST'])
def post_user_keys(user_id):
    """
    Creates a User_keys
    """
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    if not request.get_json():
        abort(400, description="Not a JSON")
    if 'name' not in request.get_json():
        abort(400, description="Missing name")

    data = request.get_json()
    instance = User_keys(**data)
    instance.user_id = user.id
    instance.save()
    return make_response(jsonify(instance.to_dict()), 201)


@app_views.route('/user_keyss/<user_keys_id>', methods=['PUT'], strict_slashes=False)
@swag_from('documentation/user_keys/put_user_keys.yml', methods=['PUT'])
def put_user_keys(user_keys_id):
    """
    Updates a User_keys
    """
    user_keys = storage.get(User_keys, user_keys_id)
    if not user_keys:
        abort(404)

    if not request.get_json():
        abort(400, description="Not a JSON")

    ignore = ['id', 'user_id', 'created_at', 'updated_at']

    data = request.get_json()
    for key, value in data.items():
        if key not in ignore:
            setattr(user_keys, key, value)
    storage.save()
    return make_response(jsonify(user_keys.to_dict()), 200)
