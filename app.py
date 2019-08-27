from flask import Flask, jsonify, request, json, session, render_template, redirect, url_for, send_file
from flask_jsonschema_validator import JSONSchemaValidator
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (create_access_token, create_refresh_token,JWTManager, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt, decode_token)
from flask_login import logout_user, LoginManager
import flask_login
import pymongo
import requests
from pymongo import MongoClient
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, AnyOf
from werkzeug.utils import secure_filename
import os
from flask_google_recaptcha import GoogleReCaptcha
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)
JSONSchemaValidator(app = app, root = "schemas")
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "60 per minute"]
)

RECAPTCHA_ENABLED = True
RECAPTCHA_SITE_KEY = os.environ.get('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY')
RECAPTCHA_THEME = "dark"
RECAPTCHA_TYPE = "image"
RECAPTCHA_SIZE = "compact"
RECAPTCHA_RTABINDEX = 10

client = MongoClient()

recaptcha = RecaptchaField()

try:
    secret = os.environ.get('SECRET')
    app.config['MONGO_URI'] = "mongodb+srv://test:test@cluster0-y1b2f.mongodb.net/test?retryWrites=true&w=majority"

except:
    db_link = os.environ.get('MONGO_URI')
    secret = os.environ.get('SECRET')

recaptcha = GoogleReCaptcha(app=app)


# uploads_dir = os.path.join(app.instance_path,'uploads')
# os.makedirs(uploads_dir,0o777,exist_ok=True)

APP_URL = "https://snapchatportal.herokuapp.com/"

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
# app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['MONGO_DBNAME'] = os.environ.get('DB_NAME') 
app.config['TESTING'] = False


mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

REQ_FILE_TYPE = ['png']

blacklist = set()

def is_human(captcha_response):
    """ Validating recaptcha response from google server
        Returns True captcha test passed for submitted form else returns False.
    """
    secret = os.environ.get('RECAPTCHA_SECRET_KEY')
    payload = {'response':captcha_response, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


@app.route('/register', methods=['POST'])
@app.validate( 'users', 'register' )
# @cross_origin()
def register():
    users = mongo.db.users
    name = request.get_json()['name']
    email = request.get_json()['email']
    response = users.find_one({"email" : email})
    if response is not None:
        return jsonify({"err":  "User already exists"})
        
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
   

    print(name, email, type(password))
    try:
        new_user = {
            'name' : name, 
            'email' : email, 
            'password' : password, 
        }
        user_id = users.insert_one(new_user)

        access_token = create_access_token(identity = new_user["name"])
        refresh_token = create_refresh_token(identity = new_user["name"])
        print(access_token, refresh_token)
        return jsonify({
                "message": "User {} was created".format(new_user["name"]),
                "access_token": access_token,
                "refresh_token": refresh_token
                })

    except:
        return jsonify({"message": "Something went wrong", "status": 500})

    result = {"email" : new_user["email"] + " registered"}

    return jsonify({
        "status": 200,
        "message": new_user["email"] + " registered"})
    

@app.route('/')
# @cross_origin()
def index():
    return redirect(url_for('login'))
    # return jsonify({"msg" : "hello"})

@app.route('/login', methods=['POST'])
@app.validate( 'users', 'login' )
# @cross_origin()
def login():
    users = mongo.db.users
    print(request.data)

    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
    response = users.find_one({"email" : email})

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

            dict_token = {
                'token_id' : access_token  
                }

            dict_email = {
                'email' : email 
                }
        else:
            result = {'status': 404,
                        'message': 'wrong password'
            }          
    else:
        result = {'status': 404,
                        'message': 'user not registered'
            }
    return jsonify(result)
	

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

# @CORS
@app.route('/upload', methods = ['POST'])
@limiter.limit("100 per hour")
# @cross_origin()
def upload():
    #Authorization
    # captcha_response = request.form['g-captcha-response']
    # if not is_human(captcha_response):
    #    return jsonify({"err": "captcha not recognised"})
    # jwt_token = request.headers.get("Authorization")
    # try:

    user_data = decode_token(jwt_token)
    print(user_data)
    # except:
    #     return jsonify({"err": "You don't have access"})
    if (request.files['filter']):
        filter = request.files['filter']
        mongo.save_file(filter.filename, filter)
        mongo.db.users.insert_one({'username': user_data.email, 'uploaded_filter_name' : filter.filename})
        print("success")
        return jsonify({"msg": "Filter uploaded"}), 200
    else:
        print("error")
        return jsonify({
            "err" : "There was some error"
        })


@app.route('/file/<filename>')
def file(filename):
    return mongo.send_file(filename)

if __name__ == '__main__':
    app.run(debug=True)

      
app.config['ENV'] = 'development'

# app.config['TESTING'] = True
