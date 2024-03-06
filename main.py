from datetime import date
from sqlalchemy.exc import IntegrityError

from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps

from sqlalchemy.testing.schema import mapped_column
from werkzeug.security import generate_password_hash, check_password_hash
import forms

app = Flask(__name__)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)
app.config['SECRET_KEY'] = 'your_secret_key'
boostrap = Bootstrap5(app)
login_manager = LoginManager(app)


# class Admin(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     # Add other fields as necessary
#
#
# class Technician(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     # Add other fields as necessary
#
#
# class Student(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     # Add other fields as necessary


@app.route('/')
def display_home():
    return render_template('home.html')


@app.route('/login/<user>', methods=['GET', 'POST'])
def display_login(user):
    if user == '1':
        # this is the action code for logging in an administrator, the value one will be passed to the login function
        # to call the admin login
        form = forms.Login()
        if form.validate_on_submit():
            # the code to access the database and check for records existing would go here
            # if a record exists then the admin would be logged in and the admin dashboard will be shown.
            # if nothing exists then the program will abort and generate an error message
            user_info = 'This will be the information for that admin from the database'
            return redirect(url_for('display_admin_dashboard', user=user_info))
        return render_template('login.html', form=form)
    elif user == '2':
        # this will be the student login action
        form = forms.Login()
        if form.validate_on_submit():
            # this will be the form for validating if the user is a student this code will search the database and
            # check for that user existing, if it doesn't the program will abort if the user is authenticated
            # successfully then the user will be redirected to the student dashboard where they can upvote existing
            # posts and create new issues
            user_info = 'The info of the student taken from the database'
            return redirect(url_for('display_student_dashboard', user=user_info))
        return render_template('login.html', form=form)
    elif user == '3':
        # this will be technician login
        pass


@app.route('/register', methods=['GET', 'POST'])
def display_student_registration():
    form = forms.StudentRegistration()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = generate_password_hash(form.password.data, salt_length=8)
        # try:
        #     pass

        # this code block will be for checking if a user already exists in a database and adding if they dont exist.
        flash('This email already exists!')
        return redirect(url_for('display_student_registration'))

    return render_template('register.html', form=form)


@app.route('/register_technician', methods=['GET', 'POST'])
def display_technician_registration():
    return render_template('register.html')


@app.route('/dashboard/<email>')
def display_dashboard(email: str):
    return render_template('dashboard.html')


@app.route('/viewIssue', methods=['GET'])
def display_issue():
    return 'View issue'


@app.route('/addIssue', methods=['GET', 'POST'])
def display_add():
    return 'Create issue'


@app.route('/forgotPassword', methods=['GET', 'POST'])
@app.route('/resetPassword', methods=['GET', 'POST'])
def display_resetpassword():
    return 'Reset password'


if __name__ == "__main__":
    # with app.app_context():
    #     db.create_all()
    app.run(debug=True)
