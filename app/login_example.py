
from flask import Flask, render_template, url_for, request, session, redirect, flash, json, jsonify
from flask_pymongo import PyMongo
import bcrypt

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'student_db'
app.config['MONGO_URI'] = 'mongodb+srv://test:test@cluster0-mlywv.mongodb.net/test?retryWrites=true&w=majority'

mongo = PyMongo(app)

@app.route('/')
def index():
    if 'username' in session:
        return 'You are logged in as ' + session['username']
    return render_template('index.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username')
        return "Logged out"
    return redirect({{ url_for('index') }})

@app.route('/login', methods=['POST'])
def login():
    error = ''
    try:
        if request.method=="POST":
            users = mongo.db.users
            attempted_username = request.form['username']
            attempted_password = request.form['pass']
            #flash(attempted_username)
            #flash(attempted_password)
            login_user = users.find_one({'name' : request.form['username']})
            if login_user:
                if bcrypt.hashpw(request.form['pass'].encode('utf-8'), login_user['password']) == login_user['password']:
                    session['username'] = request.form['username']
                    return redirect(url_for('dashboard'))
                else:
                    "Invalid password! Try again."

            return 'Invalid username/password combination'
        return render_template('index.html', error = error)



    except Exception as e:
        #flash(e)
        return render_template("index.html", error = error)
    
    
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return "You have logged in as " + session['username']

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name' : request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users.insert({'name' : request.form['username'], 'password' : hashpass})
            session['username'] = request.form['username']
            return redirect(url_for('index'))

        return 'That username already exists!'

    return render_template('index2.html')

if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(debug=True)