from flask import Flask, render_template, redirect, url_for, flash, request
from flask_mail import Mail, Message
from random import *
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import desc
from functools import wraps
from flask import session
import re
from datetime import datetime, timezone

utc_timezone = timezone.utc
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
    user = db.relationship('User', backref='role')


class User(UserMixin, db.Model):
    User_ID = db.Column(db.Integer, primary_key=True)
    Role_ID = db.Column(db.Integer, db.ForeignKey('role.Role_ID'), nullable=False)
    students = db.relationship('Student', backref='user', uselist=False)
    admins = db.relationship('Admin', backref='user', uselist=False)
    technicians = db.relationship('Technician', backref='user', uselist=False)

    def get_id(self):
        return str(self.User_ID)


class Student(db.Model):
    Student_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False, unique=True)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    Password = db.Column(db.String(100), nullable=False)

    # Define other student fields here


class Admin(db.Model):
    Admin_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False, unique=True)
    First_name = db.Column(db.String(50), nullable=False)
    Last_name = db.Column(db.String(50), nullable=False)
    Password = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    technicians = db.relationship('Technician', backref='admin')

    # Define other admin fields here


class Technician(db.Model):
    Technician_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False, unique=True)
    Admin_ID = db.Column(db.Integer, db.ForeignKey('admin.Admin_ID'), nullable=False)
    First_name = db.Column(db.String(50), nullable=False)
    Last_name = db.Column(db.String(50), nullable=False)
    Residing_area = db.Column(db.String(70), nullable=False)
    Phone_number = db.Column(db.String(20), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    Job_description = db.Column(db.String(100), nullable=False)
    faults = db.relationship('Fault', backref='Technician')
    # Define other technician fields here


class Campus(db.Model):
    Campus_ID = db.Column(db.Integer, primary_key=True)
    Campus_location = db.Column(db.String(100), nullable=False)
    Campus_name = db.Column(db.String(100), nullable=False)
    Blocks = db.Column(db.JSON, nullable=False, default=[])  # Storing block information in JSON format
    Campus_map_url = db.Column(db.String(200))
    faults = db.relationship('Fault', backref='campus')


class Fault(db.Model):
    Fault_ID = db.Column(db.Integer, primary_key=True)
    Campus_ID = db.Column(db.Integer, db.ForeignKey('campus.Campus_ID'), nullable=False)
    Block = db.Column(db.String(50), nullable=False)  # Storing the block as a string
    Location = db.Column(db.String(100))
    Description = db.Column(db.Text, nullable=False)
    Fault_Type = db.Column(db.String(50), nullable=False)
    Date_submitted = db.Column(db.DateTime, nullable=False, default=datetime.now(utc_timezone))
    Upvotes = db.Column(db.JSON, nullable=False, default=[])  # Using JSON type for Upvotes
    Status = db.Column(db.String(50), nullable=False, default='In Progress')
    Technician_ID = db.Column(db.Integer, db.ForeignKey('technician.Technician_ID'), nullable=True)
    fault_log = db.Column(db.String(100), nullable=True)


@login_manager.user_loader
def load_user(User_ID):
    return db.session.get(User, User_ID)


def get_username_from_email(email):
    # Split the email address at the "@" symbol
    parts = email.split("@")
    # Return the part before the "@" symbol
    return parts[0]


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
                return redirect(url_for('display_home'))
        return render_template('login.html', form=form)
    elif user == '2':
        # this will be the Tech login action
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            technician = db.session.execute(db.select(Technician).where(Technician.Email == email)).scalar()
            if technician:
                if check_password_hash(password=password, pwhash=technician.Password):
                    logged_in_user = db.session.execute(
                        db.select(User).where(User.User_ID == technician.User_ID)).scalar()
                    login_user(logged_in_user)
                    return redirect(url_for('display_technician_dashboard'))
            else:
                flash('User does not exist')
                return redirect(url_for('display_login', user='2'))
        return render_template('login.html', form=form)
    elif user == '3':
        # Admin login
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            print(5)
            admin = db.session.execute(db.select(Admin).where(Admin.Email == email)).scalar()
            if admin:
                if admin.Password == 'admin123':
                    logged_in_user = db.session.execute(db.select(User).where(User.User_ID == admin.User_ID)).scalar()
                    login_user(logged_in_user)
                    print(current_user.User_ID)
                    return redirect(url_for('display_home'))
                    # this log in a user at this point
            else:
                flash('User does not exist')
                return redirect(url_for('display_login', user='3'))
        return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def display_registration():
    form = forms.StudentRegistration()

    if request.method == 'POST':
        if form.validate_on_submit():
            email = form.email.data
            user_exists = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
            if user_exists:
                flash('This User exists already!')
                return redirect(url_for('display_registration'))

            if validate_student_email(email):
                session['email'] = email
                session['password'] = form.password.data
                msg = Message(subject='OTP', sender='dutmaintenance@gmail.com', recipients=[email])
                msg.body = "Use this One-Time-Pin to verify your email: \n" + str(otp)
                mail.send(msg)

                return redirect(url_for('verify'))
            else:
                flash("Email not valid", "error")

        if 'email' in session and 'password' in session:
            form.email.data = session['email']
            form.password.data = session['password']

    return render_template('register.html', form=form)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    verify_form = forms.Verify()

    if verify_form.validate_on_submit():
        user_otp = verify_form.OTP.data
        if otp == int(user_otp):
            # Retrieve form data from session
            email = session.get('email')
            password = session.get('password')
            user_record = User(Role_ID=2)
            db.session.add(user_record)
            db.session.commit()
            last_inserted_user = User.query.order_by(desc(User.User_ID)).first()
            student_record = Student(User_ID=last_inserted_user.User_ID,
                                     Email=email,
                                     Password=generate_password_hash(password, salt_length=8))
            db.session.add(student_record)
            db.session.commit()
            # Now you can use the email and password to complete the registration process
            flash('Email verified', 'success')
            return redirect(url_for('display_login', user=1))  # Redirect to the home page after verification
        else:
            flash('Incorrect OTP, please try again', 'error')
            return redirect(url_for('verify'))  # Redirect back to the verification page

    return render_template('verify.html', form=verify_form)


def validate_student_email(email):
    if not re.match(r'^\d{8}@dut4life\.ac\.za$', email):
        return False
    year = int(email[:2])
    current_year = datetime.now().year % 100
    if year > current_year:
        return False
    return True


def get_campus_info():
    campus = db.session.execute(db.select(Campus)).scalars()
    return campus


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
        residing_area = form.residing_area.data
        user = User(Role_ID=3)
        db.session.add(user)
        db.session.commit()
        last_inserted_user = User.query.order_by(desc(User.User_ID)).first()
        admin_record = db.session.execute(db.select(Admin).where(Admin.User_ID == current_user.User_ID)).scalar()
        technician = Technician(First_name=first_name,
                                Last_name=last_name,
                                Phone_number=phone_number,
                                Email=email,
                                Residing_area=residing_area,
                                Job_description=job_desc,
                                Admin_ID=admin_record.Admin_ID,
                                User_ID=last_inserted_user.User_ID
                                )
        db.session.add(technician)
        db.session.commit()
        flash('Registration Complete')
        return redirect(url_for('display_admin_dashboard'))
    return render_template('register.html', form=form)


@app.route('/student_dashboard')
@login_required
def display_student_dashboard():
    if current_user.Role_ID != 2:
        flash('Route access not allowed!')
        return redirect(url_for('display_home'))

    student = db.session.execute(db.select(Student).where(Student.User_ID == current_user.User_ID)).scalar()
    student_id = student.Student_ID
    all_faults = db.session.execute(db.select(Fault)).scalars()
    upvoted_faults = []
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    for fault in all_faults:
        if student_id in fault.Upvotes:
            upvoted_faults.append(fault)

    student_info = {"username": get_username_from_email(student.Email),
                    "email": student.Email}
    return render_template('student_dashboard.html', faults=upvoted_faults, student_info=student_info,campus_names=campus_names)


@app.route('/technician_dashboard')
@login_required
def display_technician_dashboard():
    technician = db.session.execute(db.select(Technician).where(Technician.User_ID == current_user.User_ID)).scalar()
    technician_id = technician.Technician_ID
    all_faults = db.session.execute(db.select(Fault)).scalars()
    upvoted_faults = []
    for fault in all_faults:
        if technician_id == fault.Technician_ID:
            upvoted_faults.append(fault)
    return render_template('dashboard.html', faults=upvoted_faults)


@app.route('/admin_dashboard')
@login_required
def display_admin_dashboard():
    admin = db.session.execute(db.select(Admin).where(Admin.User_ID == current_user.User_ID)).scalar()
    admin_id = admin.Admin_ID

    return render_template('dashboard.html')


@app.route('/viewIssue', methods=['GET'])
def display_issue():
    issues = db.session.execute(db.select(Fault)).scalars()

    def get_upvotes_length(obj):
        return len(obj.Upvotes)

    # Sort the list of objects based on the lengths of their 'upvotes' field
    sorted_list = sorted(issues, key=get_upvotes_length, reverse=True)
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    return render_template('view_issue.html', faults=sorted_list, campus_names=campus_names)


@app.route('/upvote_issue/<fault_id>', methods=['GET', 'POST'])
@login_required
def upvote_issue(fault_id):
    if current_user.Role_ID != 2:
        flash('Only a student is allowed to escalate issues!')
        return redirect('display_home')
    print(1)

    try:
        # Fetch the issue record using .first() for single result
        issue_record = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
        if not issue_record:
            print(2)
            flash('Fault record does not exist')
            return redirect(url_for('display_home'))

        print(3)
        if current_user.User_ID in issue_record.Upvotes:
            flash('Cannot upvote twice!')
            return redirect(url_for('display_home'))

        print(4)
        # Ensure Upvotes is mutable (list) within JSON
        if not issue_record.Upvotes:
            issue_record.Upvotes = []
        new_votes = issue_record.Upvotes.copy()  # Avoid modifying original data
        student = db.session.execute(db.select(Student).where(Student.User_ID == current_user.User_ID)).scalar()
        new_votes.append(student.Student_ID)

        # Update using jsonb_set (adjust for your database)
        issue_record.Upvotes = new_votes
        db.session.commit()
        flash('Successfully escalated!')
    except Exception as e:
        print(f"An error occurred: {e}")
        flash('An error occurred while upvoting')
        return redirect(url_for('display_home'))

    return redirect(url_for('display_home'))


@app.route('/addIssue', methods=['GET', 'POST'])
@login_required
def display_add_issue():
    if current_user.Role_ID != 2:
        flash('Action not allowed!')
        return redirect(url_for('display_home'))
    form = forms.ReportIssue()
    campuses = [campus.Campus_name for campus in get_campus_info()]
    blocks = {campus.Campus_name: campus.Blocks for campus in get_campus_info()}
    form.campus.choices = [(campus, campus) for campus in campuses]
    form.block.choices = [(block, block) for block in blocks[campuses[0]]]
    campus_img_dict = {campus.Campus_name: campus.Campus_map_url for campus in get_campus_info()}
    form.fault_type.choices = [("Electrical", "Electrical"), ("Plumbing", "Plumbing"), ("Civil", "Civil")]
    student = db.session.execute(db.select(Student).where(Student.User_ID == current_user.User_ID)).scalar()
    student_id = student.Student_ID
    if request.method == 'POST':
        print(2)
        fault_entry = Fault(Campus_ID=(
            db.session.execute(db.select(Campus).where(Campus.Campus_name == form.campus.data)).scalar()).Campus_ID,
                            Block=form.block.data,
                            Location=form.location.data,
                            Fault_Type=form.fault_type.data,
                            Upvotes=[student_id],
                            Status="Pending",
                            Description=form.issue_summary.data)

        db.session.add(fault_entry)
        db.session.commit()
        return redirect(url_for('display_home'))

    return render_template('add_issue.html', form=form, blocks=blocks, campus_img_dict=campus_img_dict)


@app.route('/forgotPassword', methods=['GET', 'POST'])
@app.route('/resetPassword', methods=['GET', 'POST'])
def display_reset_password():
    return 'Reset password'


@app.route('/login_redirect')
def do_redirect():
    return redirect(url_for('display_login', user=1))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('display_home'))


login_manager.login_view = "do_redirect"
login_manager.login_message = u"Please login to complete this action"
login_manager.login_message_category = "info"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
