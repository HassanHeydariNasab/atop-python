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
db = client.test

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
        return jsonify({'status': 400, 'message': 'IT_IS_NOT_JSON'})
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
        return jsonify({'status': 400, 'message': 'MALFORMED_MOBILE'})
    if db.users.find_one({'mobile': j['mobile']}, projection={'mobile': 1}) != None:
        return jsonify({'status': 444, 'message': 'ALREADY_REGISTERED'})
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
        return jsonify({'status': 500, 'message': 'SMS_FAILED'})
    except HTTPException as e:
        print(e)
        return jsonify({'status': 500, 'debug': 'SMS_FAILED'})
    except Exception as e:
        print(e)
        return jsonify({'status': 500, 'debug': 'SMS_FAILED'})
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
        return jsonify({'status': 400, 'message': 'IT_IS_NOT_JSON'})
    j = request.get_json()
    schema = {
        'mobile': {'type': 'string', 'maxlength': 30},    
        'code': {'type': 'string', 'maxlength': 5, 'minlength': 5}
    }
    V = Validator(schema)
    if not V.validate(j):
        return jsonify({'status': 400, 'message': V.errors})
    user_registration_info = r_register.hgetall(j['mobile'])
    if j['code'] != user_registration_info['code']:
        return jsonify({'status': 403, 'message': 'INVALID_CODE'})
    r_register.delete(j['mobile'])
    token = ''.join(SystemRandom().choice(
        string.ascii_uppercase + string.digits) for alphnm in range(32))
    db.users.insert_one(
        {
            'mobile': j['mobile'],
            'name': user_registration_info['name'],
            'password': user_registration_info['password'],
            'token': token,
            'remaining_likes': 100,
            'remaining_posts': 100,
            'earned_likes': 0
        }
    )
    return jsonify({'status': 201, 'token': token})


@app.route('/v1/login', methods=['POST'])
def login_user():
    if not request.is_json:
        return jsonify({'status': 400, 'message': 'IT_IS_NOT_JSON'})
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
    if check_password(j['password'].encode('utf8'), user['password']):
        return jsonify({'status': 200, 'token': user['token']})
    else:
        return jsonify({'status': 403})


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
        sort=[('likes', -1)]
    )
    if post == None:
        return jsonify({'status': 404})
    return jsonify({'status': 200, 'post': post})



@app.route('/')
def hello():
    return 'Hello World!'
