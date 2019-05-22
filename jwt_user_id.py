import jwt
from local_config import SECRET


def generate_token(user_id: str) -> str:
    return jwt.encode({'user_id': user_id}, key=SECRET, algorithm='HS256').decode('utf8')

def decode_user_id(token: str) -> str:
    try:
        decoded = jwt.decode(token, SECRET, algorithms='HS256')
        user_id = decoded['user_id']
    except (KeyError, jwt.exceptions.PyJWTError):
        return ''
    else:
        return str(user_id)
