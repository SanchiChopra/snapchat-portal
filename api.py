from flask import Flask, jsonify, request, json, session, render_template, redirect, url_for
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
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

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secret
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['MONGO_URI'] = db_link
app.config['MONGO_DBNAME'] = 'student_db'



mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

blacklist = set()

CORS(app)

@app.route('/')
def index():
    #session = request.get_json()
    # if session_
    # if 'email' in session:
    #     return 'You are logged in as ' + session['email']
    return render_template('index.html')

@app.route('/users/register', methods=['POST'])
def register():
    users = mongo.db.users
    name = request.get_json()['name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.now()

    try:
        user_id = users.insert({
	        'name' : name, 
	        'email' : email, 
	        'password' : password, 
	        'created' : created, 
	    })
        new_user = users.find_one({'_id' : user_id})


        access_token = create_access_token(identity = data['name'])
        refresh_token = create_refresh_token(identity = data['name'])
        return {
                'message': 'User {} was created'.format(data['name']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }

    except:
        return {'message': 'Something went wrong'}, 500

    

    # result = {'email' : new_user['email'] + ' registered'}

    return jsonify({
        "status": 200,
        "message": new_user['email'] + ' registered'})
	

@app.route('/users/login', methods=['POST'])
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
            access_token.save_to_db(access_token)
        else:
            result = {'status': 404,
                        'message': 'wrong password'
            }          
    else:
        result = {'status': 404,
                        'message': 'user not registered'
            }
    return jsonify(result)
	

def save_to_db(self):
        email = request.get_json()['email']
        tokens = mongo.db.tokens
        tokens_id = tokens.insert({
	        'token_id' : tokens,
	        'email' : email 
	    })

'''@app.route('/users/logout',methods = ['POST'])
@flask_login.login_required
def logout():
    logout_user()
    print(url_for('login'))
    return jsonify({"redirect": "why not"})'''

@app.route('/logout2', methods=['DELETE'])
@jwt_refresh_token_required
def logout2():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200

app.config['TESTING'] = False

if __name__ == '__main__':
    app.run(debug=True)