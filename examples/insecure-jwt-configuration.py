import jwt

# Test insecure JWT configurations

payload = {
    "admin": True,
    "name": "Example",
    "iat": 1794160560,
    "sub": "123456789"
}

key = "123"

headers = {
    "alg": None,
    "typ": "JWT"
}
jwt_token_bad_key = jwt.encode(payload=payload, key="123456", algorithm="HS256", headers=headers)
jwt_token_no_algorithm = jwt.encode(payload=payload, key="superduperawesomekey", algorithm=None, headers=headers)
jwt_token_positional_args_var = jwt.encode(payload, key, "HS256", headers)

jwt_token_decode_bad_key = jwt.decode(jwt_token_bad_key, key, ["HS256"], headers)

