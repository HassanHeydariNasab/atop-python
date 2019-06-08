def normalized_mobile(mobile: str) -> str:
    if mobile[0] == '+':
        mobile = mobile[1:]
    if mobile[:2] != '00':
        mobile = '00' + mobile
    return mobile
