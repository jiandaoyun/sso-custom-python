from datetime import datetime, timedelta
from flask import Flask, abort, redirect, request
import jwt

from jwt import InvalidTokenError


class Const:
    ACS = 'https://www.jiandaoyun.com/sso/custom/5cd91fe50e42834f41b7c6ef/acs'
    SECRET = 'jdy'
    ISSUER = 'com.example'
    USERNAME = 'angelmsger'


app = Flask(__name__)


def valid_token(query):
    try:
        token = jwt.decode(
            query, Const.SECRET,
            audience=Const.ISSUER,
            issuer='com.jiandaoyun'
        )
        return token.get('type') == 'sso_req'
    except InvalidTokenError:
        return False


def get_token_from_username(username):
    now = datetime.utcnow()
    return jwt.encode({
        "type": "sso_res",
        'username': username,
        'iss': Const.ISSUER,
        "aud": "com.jiandaoyun",
        "nbf": now,
        "iat": now,
        "exp": now + timedelta(seconds=60),
    }, Const.SECRET, algorithm='HS256').decode('utf-8')


@app.route('/sso', methods=['GET'])
def handler():
    query = request.args.get('request', default='')
    state = request.args.get('state')
    if valid_token(query):
        token = get_token_from_username(Const.USERNAME)
        stateQuery = "" if not state else f"&state={state}"
        return redirect(f'{Const.ACS}?response={token}{stateQuery}')
    else:
        return abort(404)


if __name__ == '__main__':
    app.run(port=8080)
