import sqlite3
import hashlib, os
from flask import Flask, render_template, request, url_for, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
#from flask_sslify import SSLify
from flask_restful import Api, Resource
from flask_httpauth import HTTPBasicAuth
from werkzeug.exceptions import abort
from cryptography.fernet import Fernet
#from app.config.config import get_config_by_name
#from app.initialize_functions import initialize_route, initialize_db, initialize_swagger

def create_app(config=None) -> Flask:
    """
    Create a Flask application.

    Args:
        config: The configuration object to use.

    Returns:
        A Flask application instance.
    """
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    
    #app.config["SECRET_KEY"] = os.urandom(16).hex()
    
    
    #sslify = SSLify(app) #HTTPS (Hypertext Transfer Protocol Secure -- Requests  redirects to ensure secure communication between  clients and the server.)
    api = Api(app)
    auth = HTTPBasicAuth()
    
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)

    
    #if config:
        #app.config.from_object(get_config_by_name(config))

    # Initialize extensions
    #initialize_db(app)

    # Register blueprints
    #initialize_route(app)    
    
    # Initialize Swagger
    #initialize_swagger(app)
    
    @auth.verify_password
    def verify_password(username, password):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            #Secure SQL Query Using to Parameterized Query prevent SQL Injection Attack
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
                
            with sqlite3.connect("database.db") as users:
                cursor = users.cursor()
                cursor.execute("INSERT INTO PROFILE (username, password)  VALUES (?, ?)", (username, password))
                users.commit() 
            return redirect(url_for('profile'))
        return True
    
    @auth.verify_password
    def verify_password(username, password):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            #Secure SQL Query Using to Parameterized Query prevent SQL Injection Attack
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            
            with sqlite3.connect("database.db") as users:
                cursor = users.cursor()
                cursor.execute("INSERT INTO PROFILE (username, password)  VALUES (?, ?)", (username, password))
                users.commit() 
            return redirect(url_for('login'))
        return True
    
    class SecureResource(Resource):
        @auth.login_required
        def get(self):
            return {'message': 'This is a secure endpoint'}
    
    #Connecting the database
    def get_db_connection():
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        return conn
    
    #Posting
    def get_post(post_id):
        conn = get_db_connection()
        post = conn.execute('SELECT * FROM posts WHERE id = ?',
                        (post_id,)).fetchone()
        conn.close()
        if post is None:
            abort(404)
        return post
    
    @app.route('/')
    def index():
        conn = get_db_connection()
        posts = conn.execute('SELECT * FROM posts').fetchall()
        conn.close()
        return render_template('index.html', posts=posts)
    
    #session data encryption using the cryptography library
    def encrypt_data(data):
        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data
    
    def decrypt_data(encrypted_data):
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        return decrypted_data
    
    def update_session(uid, username, expire_time):
        session_data = f'{uid}_{username}_{expire_time}'
        encrypted_data = encrypt_data(session_data)
        session['key'] = encrypted_data
        #session[SESSION_ID_KEY] = encrypted_data
        return encrypted_data
    
    #encryption
    def encrypt():
        letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        hashlib.sha256(letters.encode()).hexdigest()
        
    @app.route('/index') 
    def home(): 
        return render_template('index.html')
    
    connect = sqlite3.connect('database.db') 
    connect.execute('CREATE TABLE IF NOT EXISTS PROFILE (username TEXT, password TEXT)') 
    
    @app.route('/<int:post_id>')
    def post(post_id):
        post = get_post(post_id)
        return render_template('post.html', post=post)
    
    #Input Entry
    @app.route('/create', methods=('GET', 'POST'))
    def create():
        if request.method == 'POST':
            title = request.form['title']
            date = request.form['date']
            description = request.form['description']
            amount = request.form['amount']
            category = request.form['category']
            
            if not title:
                flash('Title is required!')
            else:
                conn = get_db_connection()
                conn.execute('INSERT INTO posts (title, date, description, amount, category) VALUES (?, ?, ?, ?, ?)', 
                             (title, date, description, amount, category))  
                conn.commit()
                conn.close()
                return redirect(url_for('index'))          
            
        return render_template('create.html')
    
    #Editing Input
    @app.route('/<int:id>/edit', methods=('GET', 'POST'))
    def edit(id):
        post = get_post(id)
        if request.method == 'POST':
            title = request.form['title']
            date = request.form['date']
            description = request.form['description']
            amount = request.form['amount']
            category = request.form['category']
            if not title:
                flash('Title is required!')
            else:
                conn = get_db_connection()
                conn.execute('UPDATE posts SET title = ?, date = ?, description = ?, amount = ?, category = ? '
                         ' WHERE id = ?',
                         (title, date, description, amount, category, id))
                conn.commit()
                conn.close()
                return redirect(url_for('index'))
        
        return render_template('edit.html', post=post)

    #Deleting Inputs
    @app.route('/<int:id>/delete', methods=('POST',))
    def delete(id):
        post = get_post(id)
        conn = get_db_connection()
        conn.execute('DELETE FROM posts WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        flash('"{}" was successfully deleted!'.format(post['title']))
        return redirect(url_for('index'))

    #user login
    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            with sqlite3.connect("database.db") as users:
                cursor = users.cursor()
                cursor.execute("INSERT INTO PROFILE (username, password)  VALUES (?, ?)", (username, password))
                users.commit() 
                flash('User was successfully logged in!')
            return redirect(url_for('profile'))
        else:
            return render_template('login.html')

    #user registration
    @app.route('/signup', methods=['GET','POST'])  
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            with sqlite3.connect("database.db") as users:
                cursor = users.cursor()
                cursor.execute("INSERT INTO PROFILE (username, password)  VALUES (?, ?)", (username, password))
                users.commit() 
                flash('User has successfully signed up!')
            return redirect(url_for('login'))
        else:
            return render_template('signup.html')

    #user registration and login  
    @app.route('/profile', methods=['GET', 'POST'])
    def profile():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
        
            connect = sqlite3.connect('database.db') 
            cursor = connect.cursor() 
            cursor.execute('SELECT * FROM PROFILE')
        
            data = cursor.fetchall()
            return render_template('profile.html', data=data)
        return render_template('profile.html') 

    return app
