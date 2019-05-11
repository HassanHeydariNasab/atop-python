import redis


r_mobile_code = redis.StrictRedis(
    host="localhost", port=6379, db=2)


def store(mobile: str, code: str) -> None:
    r_mobile_code.set(mobile, code, ex=3600)


def is_valid(mobile: str, code: str) -> bool:
    _code = r_mobile_code.get(mobile)
    if _code is None:
        return False
    if code == _code.decode('utf8'):
        r_mobile_code.delete(mobile)
        return True
    return False
