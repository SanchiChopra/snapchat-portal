from flask import Flask, request, jsonify, session, url_for
from flask_pymongo import PyMongo
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer
import itsdangerous
import re
import hashlib
import os


app = Flask('__main__')

app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.secret_key = os.urandom(20)

mongo = PyMongo(app)
serializer = URLSafeTimedSerializer(app.secret_key)

def validateDetails(details):
    valid = True
    name = details['Name']
    email = details['Email']
    password = details['Password']
    if( not(re.match( '^.+@.+\..+$', email)) ):
        valid = False

    if( not(len(password) >= 8 
        and re.search('[A-Z]', password)
        and re.search('[a-z]', password)
        and re.search('[0-9]', password)
        and re.search('[^a-zA-Z0-9]', password) )
        ):
        valid = False

    if(valid):
        password = hashlib.md5(password.encode())
        password = password.hexdigest()
        details['Password'] = password
    return valid
        

def isNewUser(details):

    posts = mongo.db.Users
    if( posts.find_one({'Email':details["Email"]}) ):
        return False
    else:
        return True

        

@app.route('/sign_up', methods=['POST'])
def sign_up():

    session.pop('user', None)

    posts = mongo.db.Users
    UserDetails = request.get_json()

    valid = validateDetails(UserDetails)
    newUser = isNewUser(UserDetails)

    if (not valid):
        return jsonify({'Error':True, 'Msg':'Invalid Details'})
    elif (not newUser):
        return jsonify({'Error':True, 'Msg':'User Already Exists'})
    else:
        UserDetails['Email_Confirmed'] = False
        posts.insert_one(UserDetails)
        return jsonify({'Error':False, 'Msg':'New User Created'})

@app.route('/login', methods=['POST'])
def login():

    posts = mongo.db.Users    
    UserDetails = request.get_json()
    
    valid = validateDetails(UserDetails)
    newUser = isNewUser(UserDetails)

    if (not valid):
        return jsonify({'Error':True, 'Msg':'Invalid Details'})
    elif (newUser):
        return jsonify({'Error':True, 'Msg':'User Does Not Exists'})
    else:
        currentUser = posts.find_one({'Email':UserDetails['Email']})
        if(currentUser['Password'] == UserDetails['Password']):
            session['user'] = UserDetails['Email']
            return jsonify({'Error':False, 'Msg':'User Logged in'})
        else:
            return jsonify({'Error':True, 'Msg':'Invalid Password'})


@app.route('/logout', methods=['GET'])
def logout():
    if 'user' in session:
        session.pop('user', None)
        return jsonify({ 'Error':False, 'Msg':'User Logged out'})
    else:
        return jsonify({ 'Error':True, 'Msg':'No User Logged in'})


if __name__ == '__main__':
    app.run(debug=True)