from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_mail import Mail, Message
from random import *
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, JSON, desc
from functools import wraps
from flask import session
import re
from datetime import datetime

from sqlalchemy.testing.schema import mapped_column
from werkzeug.security import generate_password_hash, check_password_hash
import forms

app = Flask(__name__)

app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'dutmaintenance@gmail.com'
app.config["MAIL_PASSWORD"] = 'gbhevmvnqlqskvgd'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
otp = randint(000000, 999999)

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)
app.config['SECRET_KEY'] = 'your_secret_key'
boostrap = Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)


class Role(db.Model):
    Role_ID = db.Column(db.Integer, primary_key=True)
    Role_Name = db.Column(db.String(50), nullable=False)
    users = db.relationship('User', back_populates='role')  # Bidirectional relationship with User


class User(UserMixin, db.Model):
    User_ID = db.Column(db.Integer, primary_key=True)
    Role_ID = db.Column(db.Integer, db.ForeignKey('role.Role_ID'), nullable=False)
    role = db.relationship('Role', back_populates='users')  # Bidirectional relationship with Role
    # Define other user fields here


class Student(db.Model):
    Student_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    Password = db.Column(db.String(100), nullable=False)
    user = db.relationship('User', back_populates='student')  # Bidirectional relationship with User
    # Define other student fields here


class Admin(db.Model):
    Admin_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False)
    First_name = db.Column(db.String(50), nullable=False)
    Last_name = db.Column(db.String(50), nullable=False)
    Password = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    user = db.relationship('User', back_populates='admin')  # Bidirectional relationship with User
    # Define other admin fields here


class Technician(db.Model):
    Technician_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False)
    Admin_ID = db.Column(db.Integer, db.ForeignKey('admin.Admin_ID'), nullable=False)
    First_name = db.Column(db.String(50), nullable=False)
    Last_name = db.Column(db.String(50), nullable=False)
    Phone_number = db.Column(db.String(20), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    Job_description = db.Column(db.String(100), nullable=False)
    user = db.relationship('User', back_populates='technician')  # Bidirectional relationship with User
    # Define other technician fields here


class Campus(db.Model):
    Campus_ID = db.Column(db.Integer, primary_key=True)
    Campus_location = db.Column(db.String(100), nullable=False)
    Campus_name = db.Column(db.String(100), nullable=False)
    Blocks = db.Column(db.JSON, nullable=False, default=[])  # Storing block information in JSON format
    Campus_map_url = db.Column(db.String(200))


class Fault(db.Model):
    Fault_ID = db.Column(db.Integer, primary_key=True)
    Campus_ID = db.Column(db.Integer, db.ForeignKey('campus.Campus_ID'), nullable=False)
    Block = db.Column(db.String(50), nullable=False)  # Storing the block as a string
    Location = db.Column(db.String(100))
    Description = db.Column(db.Text, nullable=False)
    Fault_Type = db.Column(db.String(50), nullable=False)
    Upvotes = db.Column(db.JSON, nullable=False, default=[])  # Using JSON type for Upvotes
    Status = db.Column(db.String(50), nullable=False, default='In Progress')
    Technician_ID = db.Column(db.Integer, db.ForeignKey('technician.Technician_ID'), nullable=True)
    technician = db.relationship('Technician')  # Bidirectional relationship with Technician
    fault_log = db.Column(db.String(100), nullable=True)


@login_manager.user_loader
def load_user(User_ID):
    return User.query.get(User_ID)


@login_manager.user_loader
def load_user(User_ID):
    return User.query.get(User_ID)


@app.route('/')
def display_home():
    return render_template('home.html')


@app.route('/login/<user>', methods=['GET', 'POST'])
def display_login(user):
    form = forms.Login()
    if user == '1':
        # Student login
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            student = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
            if student:
                if check_password_hash(password=password, pwhash=student.Password):
                    logged_in_user = db.session.execute(db.select(User).where(User.User_ID == student.User_ID)).scalar()
                    login_user(logged_in_user)
                    return redirect(url_for('display_student_dashboard'))
                    # this log in a user at this point
            else:
                flash('User does not exist')
                return redirect(url_for('display_student_registration'))
        return render_template('login.html', form=form)
    elif user == '2':
        # this will be the Tech login action
        email = form.email.data
        password = form.password.data
        technician = db.session.execute(db.select(Technician).where(Technician.Email == email)).scalar()
        if technician:
            if check_password_hash(password=password, pwhash=technician.Password):
                logged_in_user = db.session.execute(db.select(User).where(User.User_ID == technician.User_ID)).scalar()
                login_user(logged_in_user)
                return redirect(url_for('display_technician_dashboard'))
        else:
            flash('User does not exist')
            return redirect(url_for('display_login', user='2'))
        return render_template('login.html', form=form)
    elif user == '3':
        # Admin login
        email = form.email.data
        password = form.password.data
        admin = db.session.execute(db.select(Admin).where(Admin.Email == email)).scalar()
        if admin:
            if check_password_hash(password=password, pwhash=admin.Password):
                logged_in_user = db.session.execute(db.select(User).where(User.User_ID == admin.User_ID)).scalar()
                login_user(logged_in_user)
                return redirect(url_for('display_admin_dashboard'))
                # this log in a user at this point
        else:
            flash('User does not exist')
            return redirect(url_for('display_login', user='3'))


@app.route('/register', methods=['GET', 'POST'])
def display_registration():
    form = forms.Login()
    verify_form = forms.Login()
    if request.method == 'POST':
        if form.validate_on_submit():
            email = form.email.data
            session['email'] = email
            session['password'] = form.password.data
            if validate_student_email(email):
                msg = Message(subject='OTP', sender='dutmaintenance@gmail.com', recipients=[email])
                msg.body = str(otp)
                mail.send(msg)
                return render_template('verify.html', form=verify_form)
            else:
                flash("Email not valid", "error")
        elif verify_form.validate_on_submit():
            if 'email' in session and 'password' in session:
                email = session.get('email')
                password = session.get('password')
                user_record = User(Role_ID=2)
                db.session.add(user_record)
                db.session.commit()
                last_inserted_user = User.query.order_by(desc(User.User_ID)).first()
                User_ID = last_inserted_user.User_ID
                student_record = Student(User_ID=User_ID,
                                         Email=email,
                                         Password=password)
                db.session.add(student_record)
                db.session.commit()
                flash('Registration Successful!')
                return redirect(url_for('display_home'))
    return render_template('register.html', form=form)


def validate_student_email(email):
    if not re.match(r'^\d{8}@dut4life\.ac\.za$', email):
        return False
    year = int(email[:2])
    current_year = datetime.now().year % 100
    if year > current_year:
        return False
    return True


@app.route('/register_technician', methods=['GET', 'POST'])
@login_required
def display_technician_registration():
    form = forms.TechnicianRegistration()
    if current_user.Role_ID != 1:
        return "ACCESS DENIED"

    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        phone_number = form.phone_number.data
        email = form.email.data
        job_desc = form.occupation.data
        user = User(Role_ID=3)
        db.session.add(user)
        db.session.commit()
        last_inserted_user = User.query.order_by(desc(User.User_ID)).first()
        admin_record = db.session.execute(db.select(Admin).where(Admin.User_ID == current_user.User_ID)).scalar()
        technician = Technician(First_name=first_name,
                                Last_name=last_name,
                                Phone_number=phone_number,
                                Email=email,
                                Job_description=job_desc,
                                Admin_ID=admin_record.Admin_ID,
                                User_ID=last_inserted_user.User_ID
                                )
        db.session.add(technician)
        db.session.commit()
        flash('Registration Complete')
        return redirect(url_for('display_admin_dashboard'))
    return render_template('register.html', form=form)


@app.route('/student_dashboard/<email>')
@login_required
def display_student_dashboard(email: str):
    student = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
    student_id = student.Student_ID
    all_faults = db.session.execute(db.select(Fault))
    upvoted_faults = []
    for fault in all_faults:
        if student_id in fault.Upvotes:
            upvoted_faults.append(fault)
    return render_template('dashboard.html', faults=upvoted_faults)


@app.route('/technician_dashboard/<email>')
@login_required
def display_technician_dashboard(email: str):
    technician = db.session.execute(db.select(Technician).where(Technician.Email == email)).scalar()
    technician_id = technician.Technician_ID
    all_faults = db.session.execute(db.select(Fault))
    upvoted_faults = []
    for fault in all_faults:
        if technician_id == fault.Technician_ID:
            upvoted_faults.append(fault)
    return render_template('dashboard.html', faults=upvoted_faults)


@app.route('/admin_dashboard/<email>')
@login_required
def display_admin_dashboard(email: str):
    admin = db.session.execute(db.select(Admin).where(Admin.Email == email)).scalar()
    admin_id = admin.Admin_ID

    return render_template('dashboard.html')


@app.route('/viewIssue', methods=['GET'])
def display_issue():

    return 'View issue'


@app.route('/addIssue', methods=['GET', 'POST'])
@login_required
def display_add_issue():
    return 'Create issue'


@app.route('/forgotPassword', methods=['GET', 'POST'])
@app.route('/resetPassword', methods=['GET', 'POST'])
def display_reset_password():
    return 'Reset password'


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('display_home'))


login_manager.login_view = "dislpay_login"
login_manager.login_message = u"Please login to complete this action"
login_manager.login_message_category = "info"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()


    app.run(debug=True)
