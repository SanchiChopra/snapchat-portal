from flask import Flask, jsonify, request, json, session, render_template
from flask_pymongo  import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'student_db'
app.config['MONGO_URI'] = 'mongodb+srv://test:test@cluster0-mlywv.mongodb.net/test?retryWrites=true&w=majority'
app.config['JWT_SECRET_KEY'] = 'secret'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app)

@app.route('/')
def index():
    if 'email' in session:
        return 'You are logged in as ' + session['email']
    return render_template('index.html')

@app.route('/users/register', methods=['POST'])
def register():
    users = mongo.db.users
    name = request.get_json()['name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.utcnow()

    user_id = users.insert({
	'name' : name, 
	'email' : email, 
	'password' : password, 
	'created' : created, 
	})
    new_user = users.find_one({'_id' : user_id})

    result = {'email' : new_user['email'] + ' registered'}

    return jsonify({'result' : result})
	

@app.route('/users/login', methods=['POST'])
def login():
    users = mongo.db.users
    print(request.args)
    email = request.args['email']
    password = request.args['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'name': response['name'],
				'email': response['email']}
				)
            result = access_token
        else:
            result = jsonify({"error":"Invalid username and password"})            
    else:
        result = jsonify({"result":"No results found"})
    return result
	
	
if __name__ == '__main__':
    app.run(debug=True)