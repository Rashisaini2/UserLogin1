from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
    abort,
    Blueprint
)
from config import app, db, bcrypt, User
import os
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import sys
sys.modules
sys.path.insert(0, './tosave-main')

from werkzeug.security import generate_password_hash, check_password_hash
plain_password = "qwerty"
hashed_password = generate_password_hash(plain_password)
print(hashed_password)

from models import StudentModel,db,login
# from models import UserModel,db,login

from flask_login import login_required, current_user, login_user, logout_user,LoginManager, UserMixin
from flask_sqlalchemy import sqlalchemy
import os
from os import abort
from sqlalchemy import create_engine;
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
import forms
from forms import RegistrationForm, LoginForm

engine = create_engine('sqlite:///data.db', echo=True)

app = Flask(__name__)

CSRFProtect(app)
app.secret_key = 'somesecretkeythatonlyishouldknow'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
csrf.init_app(app)

db = SQLAlchemy(app)


db.init_app(app)
login.init_app(app)
login.login_view = 'login'


@app.before_first_request
def create_tables():
    db.create_all()


@app.route('/index', methods = ['GET','POST'])
def hello_world():

    # Creating a new user when the register form validates
    if forms.RegistrationForm().validate_on_submit():
        # Creating a new user in the database
        register_form = forms.RegistrationForm()
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(username = register_form.username.data,
                    email = register_form.email.data,
                    password = hashed_password)

        db.session.add(user)
        db.session.commit()
        redirect(url_for('welcome'))
    # Signing in the user after creating them
        user = User.query.filter_by(email = forms.RegistrationForm().email.data).first()
        if user and bcrypt.check_password_hash(user.password, forms.RegistrationForm().password.data):
            login_user(user)
        # Taking the user to the authenticated side of the site
            return render_template('success.html')

    if forms.LoginForm().validate_on_submit():
        user = User.query.filter_by(email = forms.LoginForm().email.data).first()
        if user and bcrypt.check_password_hash(user.password, forms.LoginForm().password.data):
            login_user(user, remember = forms.LoginForm().remember.data)

            return render_template('success.html')

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):
        logout_user()
        return render_template('success.html')


    return render_template('index.html',
                           login_form = forms.LoginForm(),
                           register_form = forms.RegistrationForm())

@app.route('/welcome')
def welcome():
    
    return render_template('views/authenticated.html',login_form = forms.LoginForm())

@app.route('/user' , methods = ['GET','POST'])
def userlogin():
        return render_template('user.html')
# @main.route('/profile')
# @login_required
# def profile():
#     return render_template('profile.html', name=current_user.name)

# @app.route('/blogs')
# @login_required
# def blog():
#     return render_template('blog.html')


# @app.route('/register', methods=['POST', 'GET'])
# def register():
#     if current_user.is_authenticated:
#         return redirect('/blog')
     
#     if request.method == 'POST':
#         email = request.form['email']
#         username = request.form['username']
#         password = request.form['password']
 
#         if UserModel.query.filter_by(email=email).first():
#             return ('Email already Present')
             
#         user = UserModel(email=email, username=username)
#         user.set_password(password)
#         db.session.add(user)
#         db.session.commit()
#         return redirect('/login')
#     return render_template('register.html')



# @app.route('/login', methods = ['POST', 'GET'])
# def login():
#     if current_user.is_authenticated:
#         return redirect('/blogs')
     
#     if request.method == 'POST':
#         email = request.form['email']
#         user = UserModel.query.filter_by(email = email).first()
#         if user is not None and user.check_password(request.form['password']):
#             login_user(user)
#             return redirect('/blogs')
     
#     return render_template('login.html')



# @app.route('/logout')
# def logout():
#     logout_user()
#     return redirect('/blogs')

# class User(UserMixin, db.Model):
#   id = db.Column(db.Integer, primary_key=True)
#   username = db.Column(db.String(50), index=True, unique=True)
#   email = db.Column(db.String(150), unique = True, index = True)
#   password_hash = db.Column(db.String(150))
#   joined_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)

#   def set_password(self, password):
#         self.password_hash = generate_password_hash(password)

#   def check_password(self,password):
#       return check_password_hash(self.password_hash,password)



# @app.route('/register', methods = ['POST','GET'])
# def register():
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         user = User(username =form.username.data, email = form.email.data)
#         user.set_password(form.password1.data)
#         db.session.add(user)
#         db.session.commit()
#         return redirect(url_for('login'))
#     return render_template('register.html', form=form)



# @app.route('/login', methods=['GET', 'POST'])
# def login():

#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email = form.email.data).first()
#         if user is not None and user.check_password(form.password.data):
#             login_user(user)
#             next = request.args.get("next")
#             return redirect(next or url_for('home'))
#         flash('Invalid email address or Password.')    
#     return render_template('login.html', form=form)


# @app.route("/forbidden",methods=['GET', 'POST'])
# @login_required
# def protected():
#     return redirect(url_for('forbidden.html'))


# @app.route("/logout")
# # @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('home'))


@app.route('/create' , methods = ['GET','POST'])
def create():
    if request.method == 'GET':
        return render_template('createpage.html')
 
    if request.method == 'POST':
        Roll_id = request.form['Roll_id']
        name = request.form['name']
        branch = request.form['branch']
        batch = request.form['batch']
        email = request.form['email']
        dob = request.form['dob']

        student = StudentModel(
            Roll_id=Roll_id,
            name=name,
            branch=branch,
            batch=batch,
            email=email,
            dob=dob
        )
  
    try:
        db.session.add(student)
        db.session.commit()
        return render_template('success.html')
    except:
        sqlalchemy.exc.IntegrityError
        db.session.rollback()
        print(" -> Group '{}' already exists.".format(name))
        return render_template('error.html')


@app.route('/', methods = ['GET','POST'])
@app.route('/home')
def home():
    return render_template('home.html')  





# @app.route('/i')
# def index():
#     return render_template('index.html')

@app.route('/')
def RetrieveList():
    students = StudentModel.query.all()
    return render_template('datalist.html',students = students)

 
@app.route('/data/<int:id>')
def RetrieveStudent(id):
    student =StudentModel.query.filter_by(Roll_id=id).first()
    if student:
        return render_template('data.html',student=student)
    return f"Student with id ={id} Doesn't exist"  


@app.route('/data/<int:id>/edit',methods = ['GET','POST'])
def update(id):
    student = StudentModel.query.filter_by(Roll_id=id).first()

    #hobbies = student.hobbies.split(' ')
    # print(hobbies)
    if request.method == 'POST':
        if student:
            db.session.delete(student)
            db.session.commit()
            name = request.form['name']
            branch = request.form['branch']
            batch = request.form['batch']
            email = request.form['email']
            dob = request.form['dob']
            student = StudentModel(
            Roll_id=id,
            name=name,
            branch=branch,
            batch=batch,
            email=email,
            dob=dob)
            db.session.add(student)
            db.session.commit()
            return redirect('/success')
            return redirect(f'/data/{id}')
        # return redirect('/')
        return f"Student with id = {id} Does not exist"
 
    return render_template('update.html', student = student)
 

@app.route('/success')
def success():
    student = StudentModel.query.all()
    return render_template('success.html',student=student)


@app.route('/data/<int:id>/delete', methods=['GET','POST'])
@staticmethod
def delete(id):
    student = StudentModel.query.filter_by(Roll_id=id).first()
    if request.method == 'POST':
        if student:
            db.session.delete(student)
            db.session.commit()
            return redirect('/success')
        abort(404)
     #return redirect('/')
    return render_template('delete.html')

if __name__ == "__main__":
   
    app.run(host='localhost', port=5000,debug=True)