import os
import string
import datetime
from random import SystemRandom

import redis
r_register = redis.StrictRedis(host="localhost", port=6379, db=2)  # preregistration
r_password_reset = redis.StrictRedis(host="localhost", port=6379, db=3)  # password_reset codes

import bcrypt
def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())
def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password, hashed_password)

from pymongo import MongoClient
client = MongoClient()
db = client.nishe

from pymongo.collection import ReturnDocument

from bson.objectid import ObjectId

from flask import Flask, request, jsonify

from cerberus import Validator

from kavenegar import KavenegarAPI, APIException, HTTPException
try:
    KAVENEGAR_APIKEY = os.environ['KAVENEGAR_APIKEY']
except KeyError:
    print('KAVENEGAR_APIKEY not found in env')

app = Flask(__name__)


def digits_farsify(digits: str):
    return digits.replace('0', '۰').replace('1', '۱').replace(
        '2', '۲').replace('3', '۳').replace('4', '۴').replace('5', '۵').replace(
        '6', '۶').replace('7', '۷').replace('8', '۸').replace('9', '۹')


@app.route('/v1/users', methods=['POST'])
def register_user():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'maxlength': 30},
        'name': {'type': 'string', 'maxlength': 64},
        'password': {'type': 'string'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    # mobile format: +989123456789
    if j['mobile'][0] != '+':
        return jsonify({'status': 400, 'message': 'malformed_mobile'})
    if db.users.find_one({'mobile': j['mobile']}, projection={'mobile': 1}) != None:
        return jsonify({'status': 444, 'message': 'mobile_already_registered'})
    code = ''.join(SystemRandom().choice(
            string.digits) for digit in range(5))
    try:
        api = KavenegarAPI(KAVENEGAR_APIKEY)
        params = {
            'receptor': j['mobile'],
            'message': 'سلام. کد فعال‌سازی شما در نیشه: '+digits_farsify(code),
        }
        response = api.sms_send(params)
        print(response)
    except APIException as e:
        print(e)
        return jsonify({'status': 500, 'message': 'sms_failed'})
    except HTTPException as e:
        print(e)
        return jsonify({'status': 500, 'message': 'sms_failed'})
    except Exception as e:
        print(e)
        return jsonify({'status': 500, 'message': 'sms_failed'})
    else:
        r_register.hmset(j['mobile'],
            {
                'name': j['name'],
                'password': get_hashed_password(j['password'].encode('utf8')),
                'code': code
            }
        )
    return jsonify({'status': 200})


@app.route('/v1/activate', methods=['POST'])
def activate_user():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'maxlength': 30},    
        'code': {'type': 'string', 'maxlength': 5, 'minlength': 5}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    user_registration_info = r_register.hgetall(j['mobile'])
    if j['code'] != user_registration_info[b'code'].decode('utf8'):
        return jsonify({'status': 403, 'message': 'incorrect_code'})
    r_register.delete(j['mobile'])
    token = ''.join(SystemRandom().choice(
        string.ascii_uppercase + string.digits) for alphnm in range(32))
    result = db.users.insert_one(
        {
            'mobile': j['mobile'],
            'name': user_registration_info[b'name'].decode('utf8'),
            'password': user_registration_info[b'password'].decode('utf8'),
            'token': token,
            'remaining_likes': 100,
            'remaining_posts': 100,
            'earned_likes': 0,
            'is_reviewer': False
        }
    )
    user = {'_id': str(result.inserted_id), 'token': token}
    return jsonify({'status': 201, 'user': user})


@app.route('/v1/login', methods=['POST'])
def login_user():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'maxlength': 30},
        'password': {'type': 'string'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    user = db.users.find_one(
        {'mobile': j['mobile']},
        projection = {'password': 1, 'token': 1}
    )
    if user == None:
        return jsonify({'status': 403})
    if check_password(j['password'].encode('utf8'), user['password'].encode('utf8')):
        del user['password']
        user['_id'] = str(user['_id'])
        return jsonify({'status': 200, 'user': user})
    else:
        return jsonify({'status': 403})


@app.route('/v1/users/me')
def show_users_me():
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one(
        {
            'token': token
        },
        projection={'password': 0, '_id': 0}
    )
    if user == None:
        return jsonify({'status': 404})
    return jsonify({'status': 200, 'user': user})


@app.route('/v1/users/me', methods=['PATCH'])
def edit_user_name():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        'name': {'type': 'string', 'maxlength': 28, 'minlength': 1}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})    
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one_and_update(
        {
            'token': token
        },
        {
            '$set': {'name': j['name']}
        },
        projection={'_id': 1, 'name': 1},
        return_document=ReturnDocument.AFTER
    )
    if user == None:
        return jsonify({'status': 403})
    user['_id'] = str(user['_id'])
    return jsonify({'status': 200, 'user': user})


@app.route('/v1/posts', methods=['POST'])
def add_post():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        'text': {'type': 'string', 'maxlength': 200}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one(
        {
            'token': token
        },
        projection = {
            'remaining_posts': 1,
            'name': 1
        }
    )
    if user['remaining_posts'] < 1:
        return jsonify({'status': 429, 'message': 'POST_DAILY_LIMIT_EXCEEDED'})
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
    return jsonify({'status': 201, 'user': user})


@app.route('/v1/user_posts')
def show_user_posts():
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one(
        {
            'token': token
        },
        projection={'_id': 1}
    )
    if user == None:
        return jsonify({'status': 403})
    posts = list(db.posts.find(
        {
            'user._id': user['_id'],
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
    return jsonify({'status': 200, 'posts': posts})


@app.route('/v1/unreviewed_posts')
def show_unreviewed_posts():
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one(
        {
            'token': token,
            'is_reviewer': True
        },
        projection={'_id': 1}
    )
    if user == None:
        return jsonify({'status': 403})
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
    return jsonify({'status': 200, 'posts': posts})


@app.route('/v1/review_post', methods=['PATCH'])
def review_post():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        '_id': {'type': 'string', 'maxlength': 24},
        'action': {'type': 'string', 'regex': '^(accept|reject)$'}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one(
        {
            'token': token,
            'is_reviewer': True
        },
        projection={'_id': 1}
    )
    if user == None:
        return jsonify({'status': 403})
    if j['action'] == 'accept':
        update = {
            '$set': {
                'is_reviewed': True,
                'reviewer_id': user['_id']
            }
        }
    else: # if j['action'] == 'reject'
        update = {
            '$set': {
                'is_reviewed': True,
                'is_rejected': True,
                'reviewer_id': user['_id']
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
        return jsonify({'status': 404})
    elif result.modified_count == 1:
        return jsonify({'status': 200})
    else:
        return jsonify({'status': 500})


@app.route('/v1/reviewed_posts', methods=['POST'])
def show_reviewed_posts():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        'search': {'type': 'string', 'maxlength': 200}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
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
    return jsonify({'status': 200, 'posts': posts})


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
        return jsonify({'status': 404})
    post['_id'] = str(post['_id'])
    post['user']['_id'] = str(post['user']['_id'])
    return jsonify({'status': 200, 'post': post})


@app.route('/v1/like_post', methods=['PATCH'])
def like_post():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'it_is_not_JSON'})
    j = request.get_json()
    schema = {
        '_id': {'type': 'string', 'maxlength': 24}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    try:
        token = request.headers['Authorization']
    except KeyError:
        return jsonify({'status': 403})
    user = db.users.find_one(
        {
            'token': token,
        },
        projection={'remaining_likes': 1}
    )
    if user == None:
        return jsonify({'status': 403})
    if user['remaining_likes'] < 1:
        return jsonify({'status': 429, 'message': 'like_daily_limit_exceeded'})
    post = db.posts.find_one_and_update(
        {
            '_id': ObjectId(j['_id'])
        },
        {
            '$inc': {'likes': 1}
        },
        projection={
            'likes': 1, '_id': 0
        },
        return_document=ReturnDocument.AFTER
    )
    user = db.users.find_one_and_update(
        {
            '_id': user['_id']
        },
        {
            '$inc': {'remaining_likes': -1}
        },
        projection={
            'remaining_likes': 1, '_id': 0
        },
        return_document=ReturnDocument.AFTER
    )
    if post == None:
        return jsonify({'status': 404})
    else:
        return jsonify({'status': 200, 'user': user, 'post': post})


@app.route('/')
def hello():
    return 'Hello World!'
