
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
from flask_google_recaptcha import GoogleReCaptcha

RECAPTCHA_ENABLED = True
RECAPTCHA_SITE_KEY = os.environ.get('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY')
RECAPTCHA_THEME = "dark"
RECAPTCHA_TYPE = "image"
RECAPTCHA_SIZE = "compact"
RECAPTCHA_RTABINDEX = 10

try:
    import env
    secret = os.environ.get('SECRET')
    db_link = os.environ.get('DB_LINK')

except:
    db_link = os.environ.get('DB_LINK')
    secret = os.environ.get('SECRET')

app = Flask(__name__)
recaptcha = GoogleReCaptcha(app=app)
import secret_key

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['MONGO_URI'] = os.environ.get('DB_LINK')
app.config['MONGO_DBNAME'] = os.environ.get('DB_NAME') 


mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

blacklist = set()

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
    # return jsonify({'test': 'test'})


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

@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


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


# To avoid users with blacklisted tokens from
# accessing this endpoint
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'})

#<script src="https://www.google.com/recaptcha/api.js?render=6LedCasUAAAAAMwT3VYR39FQvwcw2zeKO5UiW2IS"></script>
@app.route("/submit", methods=["POST"])
def submit():

    if recaptcha.verify():
        # SUCCESS
        print("done")
        pass
    else:
        # FAILED
        pass


if __name__ == '__main__':
    app.run(debug=True)


#authorization header for other routes, type = bearer token and rest is body