import bcrypt
import os
import string
import datetime
import redis
import jwt
import r_code
import jwt_user_id
from random import SystemRandom
from pymongo import MongoClient
from kavenegar import KavenegarAPI, APIException, HTTPException
from cerberus import Validator
from flask import Flask, request, jsonify
from bson.objectid import ObjectId
from pymongo.collection import ReturnDocument
from local_config import SECRET, KAVENEGAR_APIKEY
from utils import normalized_mobile


client = MongoClient()
db = client.atop

app = Flask(__name__)


@app.route('/v1/request_code', methods=['POST'])
def request_code():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'minlength': 5, 'maxlength': 30}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    j['mobile'] = normalized_mobile(j['mobile'])
    is_user_exists = False
    if db.users.find_one({'mobile': j['mobile']}, projection={'mobile': 1}) != None:
        is_user_exists = True
    code = ''.join(SystemRandom().choice(
        string.digits) for digit in range(5))
    try:
        api = KavenegarAPI(KAVENEGAR_APIKEY)
        params = {
            'receptor': j['mobile'],
            'message': code,
        }
        response = api.sms_send(params)
        print(response)
    except APIException as e:
        print(e)
        return jsonify({'message': 'sms_failed'}), 500
    except HTTPException as e:
        print(e)
        return jsonify({'message': 'sms_failed'}), 500
    except Exception as e:
        print(e)
        return jsonify({'message': 'sms_failed'}), 500
    else:
        r_code.store(j['mobile'], code)
    return jsonify({'is_user_exists': is_user_exists}), 201


@app.route('/v1/register', methods=['POST'])
def register_user():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'minlength': 5, 'maxlength': 30},
        'name': {'type': 'string', 'maxlength': 36, 'minlength': 1},
        'code': {'type': 'string'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    j['mobile'] = normalized_mobile(j['mobile'])
    if not r_code.is_valid(j['mobile'], j['code']):
        return jsonify({'message': 'invalid mobile or code'}), 401
    if db.users.find_one({'mobile': j['mobile']}, projection={'mobile': 1}) != None:
        return jsonify({'message': 'mobile_already_registered'}), 444
    result = db.users.insert_one(
        {
            'mobile': j['mobile'],
            'name': j['name'],
            'remaining_likes': 100,
            'is_reviewer': False
        }
    )
    token = jwt_user_id.generate_token(str(result.inserted_id))
    return jsonify({'token': token}), 201


@app.route('/v1/login', methods=['POST'])
def login_user():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'minlength': 5, 'maxlength': 30},
        'code': {'type': 'string'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    j['mobile'] = normalized_mobile(j['mobile'])
    if not r_code.is_valid(j['mobile'], j['code']):
        return jsonify({'message': 'invalid mobile or code'}), 401
    user = db.users.find_one(
        {'mobile': j['mobile']}
    )
    # unexpected
    if user == None:
        return jsonify({'message': 'invalid mobile or code'}), 401
    token = jwt_user_id.generate_token(str(user['_id']))
    return jsonify({'token': token}), 200


@app.route('/v1/users/me')
def show_me():
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({}), 401
    user_id = jwt_user_id.decode_user_id(token)
    if user_id == '':
        return jsonify({}), 401
    user = db.users.find_one(
        {
            '_id': ObjectId(user_id)
        }
    )
    if user == None:
        return jsonify({}), 401
    user['_id'] = str(user['_id'])
    return jsonify({'user': user}), 200


@app.route('/v1/users/me', methods=['PATCH'])
def edit_user_name():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'name': {'type': 'string', 'maxlength': 36, 'minlength': 1}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({}), 401
    user_id = jwt_user_id.decode_user_id(token)
    if user_id == '':
        return jsonify({}), 401
    user = db.users.find_one_and_update(
        {
            '_id': ObjectId(user_id)
        },
        {
            '$set': {'name': j['name']}
        },
        projection={'_id': 1, 'name': 1},
        return_document=ReturnDocument.AFTER
    )
    if user == None:
        return jsonify({}), 401
    user['_id'] = str(user['_id'])
    return jsonify({'user': user}), 200


@app.route('/v1/posts', methods=['POST'])
def create_post():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'text': {'type': 'string', 'maxlength': 200, 'minlength': 1}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({}), 401
    user_id = jwt_user_id.decode_user_id(token)
    if user_id == '':
        return jsonify({}), 401
    user = db.users.find_one(
        {
            '_id': ObjectId(user_id)
        },
        projection={
            'name': 1
        }
    )
    if user == None:
        return jsonify({}), 401
    db.posts.insert_one(
        {
            'text': j['text'],
            'user': {
                '_id': user['_id'],
                'name': user['name']
            },
            'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0),
            'datetime': datetime.datetime.utcnow(),
            'liked': 0
        }
    )
    return jsonify({}), 201


@app.route('/v1/user_posts')
def show_user_posts():
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({}), 401
    user_id = jwt_user_id.decode_user_id(token)
    if user_id == '':
        return jsonify({}), 401
    posts = list(db.posts.find(
        {
            'user._id': ObjectId(user_id),
            'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0)
        },
        projection={
            'text': 1, 'user.name': 1, 'liked': 1,
            'is_reviewed': 1, 'is_rejected': 1, 'is_disabled': 1
        },
        sort=[('_id', -1)],
        limit=request.args.get('limit', default=10, type=int),
        skip=request.args.get('offset', default=0, type=int)
    ))
    for post in posts:
        post['_id'] = str(post['_id'])
    return jsonify({'posts': posts}), 200


@app.route('/v1/posts', methods=['GET'])
def show_posts():
    search_term = request.args.get('search', default='', type=str)
    if search_term == '':
        posts = db.posts.find(
            {
                'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0)
            },
            projection={
                'text': 1, 'user._id': 1, 'user.name': 1, 'liked': 1
            },
            limit=request.args.get('limit', default=10, type=int),
            skip=request.args.get('offset', default=0, type=int),
            sort=[('liked', -1)]
        )
    else:
        posts = db.posts.find(
            {
                'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0),
                '$text': {'$search': search_term}
            },
            projection={
                'text': 1, 'user._id': 1, 'user.name': 1, 'liked': 1, 'score': {'$meta': 'textScore'}
            },
            limit=request.args.get('limit', default=10, type=int),
            skip=request.args.get('offset', default=0, type=int),
            sort=[('score', {'$meta': 'textScore'})]
        )
    posts = list(posts)
    for post in posts:
        post['_id'] = str(post['_id'])
        post['user']['_id'] = str(post['user']['_id'])
    return jsonify({'posts': posts}), 200


@app.route('/v1/main_post')
def show_main_post():
    post = db.posts.find_one(
        {
            'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0)
        },
        projection={'user': 1, 'text': 1},
        sort=[('liked', -1)],
        limit=1
    )
    if post == None:
        return jsonify({}), 404
    post['_id'] = str(post['_id'])
    post['user']['_id'] = str(post['user']['_id'])
    return jsonify({'post': post}), 200


@app.route('/v1/posts/<post_id>', methods=['PATCH'])
def like_post(post_id):
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'liked': {'type': 'boolean'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({}), 401
    user_id = jwt_user_id.decode_user_id(token)
    if user_id == '':
        return jsonify({}), 401
    user = db.users.find_one(
        {
            '_id': ObjectId(user_id)
        }
    )
    if user == None:
        return jsonify({}), 401
    if user['remaining_likes'] < 1:
        return jsonify({'message': 'Sorry, your daily limit for like exceeded!'}), 429
    post = db.posts.find_one_and_update(
        {
            '_id': ObjectId(post_id)
        },
        {
            '$inc': {'liked': 1}
        },
        return_document=ReturnDocument.AFTER
    )
    user = db.users.find_one_and_update(
        {
            '_id': ObjectId(user_id)
        },
        {
            '$inc': {'remaining_likes': -1}
        },
        return_document=ReturnDocument.AFTER
    )
    if post == None:
        return jsonify({}), 404
    user['_id'] = str(user['_id'])
    post['_id'] = str(post['_id'])
    post['user']['_id'] = str(post['user']['_id'])
    return jsonify({'user': user, 'post': post}), 200


@app.route('/')
def hello():
    return 'Hello World!'
