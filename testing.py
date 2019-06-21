
from flask import Flask, jsonify, request, json, session, render_template, redirect, url_for
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token,JWTManager, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from flask_login import logout_user, LoginManager
import flask_login
import os

try:
    import env
    secret = env.secret
    db_link = env.db_link

except:
    db_link = os.environ('db_link')
    secret = os.environ('secret')

# Setup flask
app = Flask(__name__)

# Enable blacklisting and specify what kind of tokens to check
# against the blacklist
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['MONGO_URI'] = db_link
app.config['MONGO_DBNAME'] = 'student_db'


mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# A storage engine to save revoked tokens. In production if
# speed is the primary concern, redis is a good bet. If data
# persistence is more important for you, postgres is another
# great option. In this example, we will be using an in memory
# store, just to show you how this might work. For more
# complete examples, check out these:
# https://github.com/vimalloc/flask-jwt-extended/blob/master/examples/redis_blacklist.py
# https://github.com/vimalloc/flask-jwt-extended/tree/master/examples/database_blacklist
blacklist = set()


# For this example, we are just checking if the tokens jti
# (unique identifier) is in the blacklist set. This could
# be made more complex, for example storing all tokens
# into the blacklist with a revoked status when created,
# and returning the revoked status in this call. This
# would allow you to have a list of all created tokens,
# and to consider tokens that aren't in the blacklist
# (aka tokens you didn't create) as revoked. These are
# just two options, and this can be tailored to whatever
# your application needs.
@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


@app.route('/register', methods=['POST'])
def register():
    users = mongo.db.users
    name = request.get_json()['name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    print(name, email, type(password), created)
    try:
        new_user = {
            'name' : name, 
            'email' : email, 
            'password' : password, 
            'created' : created, 
        }
        user_id = users.insert_one(new_user)

        access_token = create_access_token(identity = new_user['name'])
        refresh_token = create_refresh_token(identity = new_user['name'])
        print(access_token, refresh_token)
        return jsonify({
                'message': 'User {} was created'.format(new_user['name']),
                'access_token': access_token,
                'refresh_token': refresh_token
                })

    except:
        return jsonify({'message': 'Something went wrong', 'status': 500})

    

    result = {'email' : new_user['email'] + ' registered'}

    return jsonify({
        "status": 200,
        "message": new_user['email'] + ' registered'})
    # return jsonify({'blejh': 'blehdh'})

# Standard login endpoint


@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    data = request.get_json()
    email = data['email']
    password = data['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'name': response['name'],
				'email': response['email']}
				)
            result = {'status': 200,
                        'token': access_token,
                        'message': 'login success'
                    }
            tokens = mongo.db.tokens
            tokens.insert_one({
                'token_id' : access_token,
                'email' : email 
            })
        else:
            result = {'status': 404,
                        'message': 'wrong password'
            }          
    else:
        result = {'status': 404,
                        'message': 'user not registered'
            }
    return jsonify(result)
	

# @app.route('/login', methods=['POST'])
# def login():
#     username = request.json.get('username', 'test')
#     password = request.json.get('password', 'test')
#     if username != 'test' or password != 'test':
#         return jsonify({"msg": "Bad username or password"}), 401

#     ret = {
#         'access_token': create_access_token(identity=username),
#         'refresh_token': create_refresh_token(identity=username)
#     }
#     return jsonify(ret), 200


# Standard refresh endpoint. A blacklisted refresh token
# will not be able to access this endpoint
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


# Endpoint for revoking the current users access token
@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200


# Endpoint for revoking the current users refresh token
@app.route('/logout2', methods=['DELETE'])
@jwt_refresh_token_required
def logout2():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200


# This will now prevent users with blacklisted tokens from
# accessing this endpoint
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'})

if __name__ == '__main__':
    app.run(debug=True)


#authorization header for other routes, type = bearer token and rest is body