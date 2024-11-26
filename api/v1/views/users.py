#!/usr/bin/python3
""" objects that handle all default RestFul API actions for Users """
from models.user import User
from models import storage
from api.v1.views import app_views
from flask import abort, jsonify, make_response, request, Flask
from flasgger.utils import swag_from
from hashlib import md5
import requests


"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
@app_views.route('/limit-5', methods=['GET'])
@limiter.limit("5 per minute")  # Specific rate limit
def my_api():
    return jsonify({'message': 'Welcome!'})
"""

@app_views.route('/weather/<latitude>/<longitude>', methods=['GET'], strict_slashes=False)
def weather(latitude, longitude):
    """
    Get a 7-day weather forecast for a given location.
    """
    try:
        latitude = float(latitude)
        longitude = float(longitude)

        points_url = f"https://api.weather.gov/points/{latitude},{longitude}"
        response = requests.get(points_url, headers={"User-Agent": "YourAppName (your_email@example.com)"})
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch grid points", "details": response.json()}), response.status_code

        points_data = response.json()

        office = points_data['properties']['gridId']
        grid_x = points_data['properties']['gridX']
        grid_y = points_data['properties']['gridY']

        forecast_url = f"https://api.weather.gov/gridpoints/{office}/{grid_x},{grid_y}/forecast"
        forecast_response = requests.get(forecast_url, headers={"User-Agent": "YourAppName (your_email@example.com)"})
        if forecast_response.status_code != 200:
            return jsonify({"error": "Failed to fetch forecast", "details": forecast_response.json()}), forecast_response.status_code

        forecast_data = forecast_response.json()
        return jsonify(forecast_data)

    except ValueError:
        return jsonify({"error": "Invalid latitude or longitude format. Please use numeric values."}), 400
    except requests.RequestException as e:
        return jsonify({"error": "An error occurred while making a request to the Weather API.", "details": str(e)}), 500


@app_views.route('/users', methods=['GET'], strict_slashes=False)
@swag_from('documentation/user/all_users.yml')
def get_users():
    """
    Retrieves the list of all user objects
    or a specific user
    """
    all_users = storage.all(User).values()
    list_users = []
    for user in all_users:
        list_users.append(user.to_dict())
    return jsonify(list_users)


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
@swag_from('documentation/user/get_user.yml', methods=['GET'])
def get_user(user_id):
    """ Retrieves an user """
    user = storage.get(User, user_id)
    if not user:
        abort(404)

    return jsonify(user.to_dict())


@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)
@swag_from('documentation/user/delete_user.yml', methods=['DELETE'])
def delete_user(user_id):
    """
    Deletes a User object by user_id
    """
    user = storage.get(User, user_id)
    if not user:
        return abort(404, description="User not found")

    try:
        storage.delete(user)
        storage.save()
    except Exception as e:
        return make_response(jsonify({"error": "Failed to delete user", "details": str(e)}), 500)

    return make_response(jsonify({"message": "User deleted successfully"}), 200)


@app_views.route('/users', methods=['POST'], strict_slashes=False)
@swag_from('documentation/user/post_user.yml', methods=['POST'])
def post_user():
    """
    Creates a user
    """
    data = request.get_json()
    if not data:
        abort(400, description="Not a JSON")

    if 'email' not in data:
        abort(400, description="Missing email")
    if 'password' not in data:
        abort(400, description="Missing password")

    email = data['email']
    users = storage.all(User).values()
    existing_user = next((user for user in users if user.to_dict().get('email') == email), None)

    if existing_user:
        return jsonify({"error": "Email already exists. Please use a different email."}), 401

    instance = User(**data)
    instance.save()

    return make_response(jsonify(instance.to_dict()), 201)


@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)
@swag_from('documentation/user/put_user.yml', methods=['PUT'])
def put_user(user_id):
    """
    Updates a user
    """
    user = storage.get(User, user_id)

    if not user:
        abort(404)

    if not request.get_json():
        abort(400, description="Not a JSON")

    ignore = ['id', 'email', 'created_at', 'updated_at']

    data = request.get_json()
    for key, value in data.items():
        if key not in ignore:
            setattr(user, key, value)
    storage.save()
    return make_response(jsonify(user.to_dict()), 200)


@app_views.route('/login', methods=['POST'], strict_slashes=False)
def login():
    data = request.get_json()

    if 'email' not in data or 'password' not in data:
        return jsonify({"error": "Invalid request"}), 400

    email = data['email']
    password = data['password']

    all_users = storage.all(User).values()
    users = []
    for user in all_users:
        users.append(user.to_dictt())

    user = next((u for u in users if u.get('email') == email), None)

    hashed_password = md5(password.encode()).hexdigest()
    if user and user.get('password') == hashed_password:
        return jsonify({"userId": user['id']}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401
