from flask_wtf import FlaskForm
from wtforms import SubmitField, PasswordField, StringField, validators, EmailField, SelectField

class Login(FlaskForm):
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')

class StudentRegistration(FlaskForm):
    name = StringField("Username", validators=[validators.DataRequired()])
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')

class TechnicianRegistration(FlaskForm):
    name = StringField("Username", validators=[validators.DataRequired()])
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    occupation_choices = [('electrical', 'Electrical'), ('plumbing', 'Plumbing'), ('civil', 'Civil')]
    occupation = SelectField("Occupation", choices=occupation_choices, validators=[validators.DataRequired()])
    phone_number = StringField("Phone Number", validators=[
        validators.Regexp(r'^\+?27?\d{9}$', message="Invalid South African phone number")
    ])
    submit = SubmitField('Submit')

class ReportIssue(FlaskForm):
    campus_choices = [('A', 'Campus A'), ('B', 'Campus B'), ('C', 'Campus C'), ('D', 'Campus D'), ('E', 'Campus E')]
    block_choices = [('A', 'Block A'), ('B', 'Block B'), ('C', 'Block C'), ('D', 'Block D'), ('E', 'Block E'),
                     ('F', 'Block F'), ('G', 'Block G'), ('H', 'Block H'), ('I', 'Block I')]

    campus = SelectField("Campus", choices=campus_choices, validators=[validators.DataRequired()])
    block = SelectField("Block", choices=block_choices, validators=[validators.DataRequired()])
    issue_summary = StringField("Issue Summary", validators=[validators.DataRequired()])
    submit = SubmitField('Submit')
