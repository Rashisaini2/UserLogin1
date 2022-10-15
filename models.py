from flask_sqlalchemy import SQLAlchemy
import sys
sys.modules
sys.path.insert(0, './tosave-main')
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import LoginManager
from flask import Flask
from sqlalchemy import create_engine

engine = create_engine('sqlite:///data.db')
connection = engine.connect()

login = LoginManager()
db =SQLAlchemy()

# class UserModel(UserMixin, db.Model):
#     __tablename__ = 'users'
 
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(20), unique = True, nullable = False)
#     email = db.Column(db.String(120), unique = True, nullable = False)
#     password_hash = db.Column(db.String(), nullable = False)

class UserModel(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

 
    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
 
 
@login.user_loader
def load_user(id):
    return UserModel.query.get(int(id))


class StudentModel(db.Model):
    __tablename__ = "students"
 
    id = db.Column(db.Integer, primary_key=True)
    Roll_id = db.Column(db.Integer(),unique = True)
    name = db.Column(db.String())
    branch = db.Column(db.String())
    batch = db.Column(db.String())
    email = db.Column(db.String(),unique = True)
    dob = db.Column(db.String())
    
    def __init__(self, Roll_id,name,branch,batch,email,dob):
        self.Roll_id = Roll_id
        self.name = name
        self.branch = branch
        self.batch = batch
        self.email = email
        self.dob = dob
        
   
    def __repr__(self):
        return f"{self.name}:{self.Roll_id}"