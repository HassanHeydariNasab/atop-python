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


client = MongoClient()
db = client.nishe

app = Flask(__name__)


def digits_farsify(digits: str):
    return digits.replace('0', '۰').replace('1', '۱').replace(
        '2', '۲').replace('3', '۳').replace('4', '۴').replace('5', '۵').replace(
        '6', '۶').replace('7', '۷').replace('8', '۸').replace('9', '۹')


@app.route('/v1/request_code', methods=['POST'])
def request_code():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'minlength': 10, 'maxlength': 30}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    is_user_exists = False
    if db.users.find_one({'mobile': j['mobile']}, projection={'mobile': 1}) != None:
        is_user_exists = True
    code = ''.join(SystemRandom().choice(
        string.digits) for digit in range(5))
    print(code)
    try:
        api = KavenegarAPI(KAVENEGAR_APIKEY)
        params = {
            'receptor': j['mobile'],
            'message': 'سلام. کد فعال‌سازی: '+digits_farsify(code),
        }
        # response = api.sms_send(params)
        # print(response)
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
        'mobile': {'type': 'string', 'minlength': 10, 'maxlength': 30},
        'name': {'type': 'string', 'maxlength': 36, 'minlength': 1},
        'code': {'type': 'string'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    if not r_code.is_valid(j['mobile'], j['code']):
        return jsonify({'message': 'invalid mobile or code'}), 401
    if db.users.find_one({'mobile': j['mobile']}, projection={'mobile': 1}) != None:
        return jsonify({'message': 'mobile_already_registered'}), 444
    result = db.users.insert_one(
        {
            'mobile': j['mobile'],
            'name': j['name'],
            'remaining_likes': 100,
            'remaining_posts': 100,
            'liked': 0,
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
        'mobile': {'type': 'string', 'minlength': 10, 'maxlength': 30},
        'code': {'type': 'string'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
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
def add_post():
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
            'remaining_posts': 1,
            'name': 1
        }
    )
    if user == None:
        return jsonify({}), 401
    if user['remaining_posts'] < 1:
        return jsonify({'message': 'Sorry, your daily limit for post exceeded!'}), 429
    db.posts.insert_one(
        {
            'text': j['text'],
            'is_reviewed': False,
            'is_rejected': False,
            'is_disabled': False,
            'user': {
                '_id': user['_id'],
                'name': user['name']
            },
            'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0),
            'datetime': datetime.datetime.utcnow(),
            'likes': 0
        }
    )
    db.users.update_one(
        {'_id': ObjectId(user['_id'])},
        {'$inc': {'remaining_posts': -1}}
    )
    user['remaining_posts'] -= 1
    del user['name']
    del user['_id']
    return jsonify({'user': user}), 201


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
            'text': 1, 'user.name': 1, 'likes': 1,
            'is_reviewed': 1, 'is_rejected': 1, 'is_disabled': 1
        },
        sort=[('_id', -1)],
        limit=request.args.get('limit', default=10, type=int),
        skip=request.args.get('offset', default=0, type=int)
    ))
    for post in posts:
        post['_id'] = str(post['_id'])
    return jsonify({'posts': posts}), 200


@app.route('/v1/unreviewed_posts')
def show_unreviewed_posts():
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({}), 401
    user_id = jwt_user_id.decode_user_id(token)
    if user_id == '':
        return jsonify({}), 401
    user = db.users.find_one(
        {
            '_id': ObjectId(user_id),
            'is_reviewer': True
        },
        projection={'_id': 1}
    )
    if user == None:
        return jsonify({}), 401
    posts = list(db.posts.find(
        {
            'is_reviewed': False,
            'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0)
        },
        projection={
            'text': 1, 'user.name': 1
        },
        limit=request.args.get('limit', default=10, type=int),
        skip=request.args.get('offset', default=0, type=int)
    ))
    for post in posts:
        post['_id'] = str(post['_id'])
    return jsonify({'posts': posts}), 200


@app.route('/v1/review_post', methods=['PATCH'])
def review_post():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        '_id': {'type': 'string', 'maxlength': 24},
        'action': {'type': 'string', 'regex': '^(accept|reject)$'}
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
            '_id': ObjectId(user_id),
            'is_reviewer': True
        },
        projection={'_id': 1}
    )
    if user == None:
        return jsonify({}), 401
    if j['action'] == 'accept':
        update = {
            '$set': {
                'is_reviewed': True,
                'reviewer_id': ObjectId(user_id)
            }
        }
    else:  # if j['action'] == 'reject'
        update = {
            '$set': {
                'is_reviewed': True,
                'is_rejected': True,
                'reviewer_id': ObjectId(user_id)
            }
        }
    result = db.posts.update_one(
        {
            '_id': ObjectId(j['_id']),
            'is_reviewed': False
        },
        update
    )
    if result.matched_count == 0:
        return jsonify({}), 404
    elif result.modified_count == 1:
        return jsonify({}), 200
    else:
        return jsonify({}), 500


@app.route('/v1/reviewed_posts', methods=['POST'])
def show_reviewed_posts():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        'search': {'type': 'string', 'maxlength': 200}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'errors': V.errors, 'message': 'invalid format'}), 400
    if j['search'] == '':
        posts = db.posts.find(
            {
                'is_reviewed': True,
                'is_rejected': False,
                'is_disabled': False,
                'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0)
            },
            projection={
                'text': 1, 'user._id': 1, 'user.name': 1, 'likes': 1
            },
            limit=request.args.get('limit', default=10, type=int),
            skip=request.args.get('offset', default=0, type=int),
            sort=[('likes', -1)]
        )
    else:
        posts = db.posts.find(
            {
                'is_reviewed': True,
                'is_rejected': False,
                'is_disabled': False,
                'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0),
                '$text': {'$search': j['search']}
            },
            projection={
                'text': 1, 'user._id': 1, 'user.name': 1, 'likes': 1, 'score': {'$meta': 'textScore'}
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
            'date': datetime.datetime.utcnow().replace(microsecond=0, second=0, minute=0, hour=0),
            'is_reviewed': True,
            'is_rejected': False,
            'is_disabled': False
        },
        projection={'user': 1, 'text': 1},
        sort=[('likes', -1)],
        limit=1
    )
    if post == None:
        return jsonify({}), 404
    post['_id'] = str(post['_id'])
    post['user']['_id'] = str(post['user']['_id'])
    return jsonify({'post': post}), 200


@app.route('/v1/like_post', methods=['PATCH'])
def like_post():
    if not request.is_json:
        return jsonify({'message': 'The request is not JSON!'}), 415
    j = request.get_json()
    schema = {
        '_id': {'type': 'string', 'maxlength': 24}
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
            '_id': ObjectId(j['_id'])
        },
        {
            '$inc': {'likes': 1}
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
    else:
        return jsonify({'user': user, 'post': post}), 200


@app.route('/')
def hello():
    return 'Hello World!'
