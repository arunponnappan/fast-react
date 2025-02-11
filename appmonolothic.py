# ========================
# IMPORTS
# ========================
# Flask & Extensions
from flask import (
    Flask, render_template, redirect, url_for, flash, 
    request, session, jsonify, abort, make_response, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, 
    login_required, current_user
)
from flask_wtf import FlaskForm
from flask_migrate import Migrate

# WTForms
from wtforms import (
    StringField, PasswordField, SubmitField, SelectField, 
    TextAreaField, DateField, IntegerField
)
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo, ValidationError, 
    Optional, URL, NumberRange,Regexp
)
from wtforms.widgets import TextArea
from flask_wtf.file import FileField, FileAllowed

# Utilities
from sqlalchemy import or_, and_, func
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from pytz import timezone, UTC
import os
import uuid
import secrets
import hmac
import hashlib
import io

# Additional Libraries
from PIL import Image, ImageOps  # For image manipulation
from xhtml2pdf import pisa        # For PDF generation



app = Flask(__name__)
application = app

# Add these security configurations xxxxxxxx
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# If behind a proxy (common in shared hosting) xxxxxx
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Add these configurations
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'  # Make sure this directory exists and is writable
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# Initialize Session
from flask_session import Session
Session(app)



import logging
from logging.handlers import RotatingFileHandler

# Set up logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/application.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MIGRATIONS_FOLDER'] = 'migrations'  # Optional: Customize folder for migrations

app.config['PROFILE_PIC_UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png'}

# blog setup
# Set the upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

# Create the folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)



db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Migrate
migrate = Migrate(app, db)

#Hooks
@app.before_request
def check_user_status():
    if current_user.is_authenticated and current_user.status == 'Inactive':
        flash('Your account is inactive. You have been logged out.', 'danger')
        logout_user()
        return redirect(url_for('login'))




# *************** Profile Module  ***************

class UpdateAccountForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Update')

class AdminPasswordForm(FlaskForm):
    password = PasswordField('Enter your password to confirm', validators=[DataRequired()])
    submit = SubmitField('Confirm Deletion')

class UpdateProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password')])
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField('Update Profile')


# Modify User model to store profile picture filename
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    profile_picture = db.Column(db.String(100), default='default.jpg')
    status = db.Column(db.String(50), nullable=False, default='Active')  # Active or Inactive

    def is_admin(self):
        return self.role == 'Admin'

    def is_staff(self):
        return self.role == 'Staff'

# User login session tracking
class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True)
    session_duration = db.Column(db.Integer, nullable=True)  # Duration in seconds
    browser = db.Column(db.String(255), nullable=True)
    location = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref=db.backref('activities', lazy=True))

    def __repr__(self):
        return f'<UserActivity {self.id}>'

def get_user_location(ip_address):
    # Check if the IP is localhost (127.0.0.1)
    if ip_address == '127.0.0.1' or ip_address == 'localhost':
        return "Localhost, Local"

    # You can replace this with a real API to get user location based on IP
    url = f"http://ip-api.com/json/{ip_address}?fields=country,city"
    response = requests.get(url)
    data = response.json()

    # Log the response for debugging
    print(f"API Response: {data}")

    if data.get("status") == "fail":
        return "Unknown"  # If API call fails, return 'Unknown'
    
    return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_profile_picture(form_picture):
    if not form_picture:
        return 'default.jpg'

    random_hex = os.urandom(8).hex()
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_filename = random_hex + f_ext
    picture_path = os.path.join(app.config['PROFILE_PIC_UPLOAD_FOLDER'], picture_filename)

    # Resize and optimize image
    output_size = (125, 125)  # Resize image to 125x125 (you can modify this)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_filename


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()

    if form.validate_on_submit():
        changes_made = False  # Track if any updates are made
        password_updated = False  # Track if the password was updated

        # Check if the email has changed and is not already in use
        if form.email.data != current_user.email:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('This email is already in use. Please choose a different email.', 'danger')
                return redirect(url_for('dashboard', tab='profile-settings') + '#profile-settings-tab')
            current_user.email = form.email.data
            changes_made = True

        # Update password only if a new password is provided
        if form.password.data:
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match!', 'danger')
                return redirect(url_for('dashboard', tab='profile-settings') + '#profile-settings-tab')
            # Hash and update password
            current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            changes_made = True
            password_updated = True  # Indicate password was updated

        # Update profile picture if provided
        if form.profile_picture.data:
            picture_file = form.profile_picture.data
            picture_filename = save_profile_picture(picture_file)
            current_user.profile_picture = picture_filename
            changes_made = True

        # Commit all changes to the database
        if changes_made:
            db.session.commit()
            if password_updated:
                flash('Your password has been updated successfully!', 'success')
            elif form.email.data != current_user.email:
                flash('Your email has been updated successfully!', 'success')
            elif form.profile_picture.data:
                flash('Your profile picture has been updated successfully!', 'success')
            else:
                flash('Your profile has been updated successfully!', 'success')
        else:
            flash('No changes were made to your profile.', 'info')
        return redirect(url_for('dashboard', tab='profile-settings') + '#profile-settings-tab')


    # Handle profile picture upload from POST request
    if request.method == 'POST' and 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = save_profile_picture(file)
            current_user.profile_picture = filename
            db.session.commit()
            flash('Your profile picture has been updated!', 'success')
            return redirect(url_for('dashboard', tab='profile-settings') + '#profile-settings-tab')       
    return render_template('profile/profile.html', form=form)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





# *************** Registration Module End ***************
# Registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('Member', 'Member'), ('Staff', 'Staff'), ('Admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')






# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Initialize the form for profile settings (default to None if not used)
    form = UpdateProfileForm() if current_user.role != 'Member' else None

    if current_user.is_admin():
        active_users = User.query.filter_by(status='Active').all()
        inactive_users = User.query.filter_by(status='Inactive').all()
        activities = UserActivity.query.all()

        # Convert login times to IST
        ist = timezone('Asia/Kolkata')
        for activity in activities:
            if activity.login_time:
                if activity.login_time.tzinfo is None:
                    activity.login_time = UTC.localize(activity.login_time)
                activity.login_time = activity.login_time.astimezone(ist)

        return render_template(
            'dashboard/admin_dashboard.html',
            active_users=active_users,
            inactive_users=inactive_users,
            activities=activities,
            form=form
        )

    elif current_user.is_staff():
        active_users = User.query.filter_by(status='Active').all()
        inactive_users = User.query.filter_by(status='Inactive').all()

        return render_template(
            'dashboard/staff_dashboard.html',
            active_users=active_users,
            inactive_users=inactive_users,
            form=form
        )

    elif current_user.role == 'Member':
        # Fetch data for member dashboard
        return render_template(
            'dashboard/member_dashboard.html',
            form=None  # Pass `form=None` explicitly
        )

    else:
        flash('Access restricted.', 'danger')
        return redirect(url_for('home'))






@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_staff() and not current_user.is_admin():
        flash('You do not have permission to create users.', 'danger')
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    
    # Restrict staff to only create member users
    if current_user.is_staff():
        form.role.data = 'Member'  # Preselect 'Member' role for staff
        form.role.render_kw = {'disabled': True}  # Disable role selection for staff

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {form.username.data} has been created!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('auth/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()

            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('login'))

            if user.status == 'Inactive':
                flash('Your account is inactive. Please contact the admin for assistance.', 'danger')
                return redirect(url_for('login'))

            if not bcrypt.check_password_hash(user.password, form.password.data):
                flash('Invalid credentials.', 'danger')
                return redirect(url_for('login'))

            login_user(user)

            # Record user activity
            try:
                user_activity = UserActivity(
                    user_id=user.id,
                    browser=request.user_agent.string,
                    location=get_user_location(request.remote_addr)
                )
                db.session.add(user_activity)
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Error recording user activity: {str(e)}")
                # Continue even if activity recording fails
                
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
                
            return redirect(next_page)
            
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            db.session.rollback()
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('auth/login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    # Check if the current user has any activity records
    if current_user.activities:
        # Capture logout details for the most recent activity
        user_activity = current_user.activities[-1]  # Most recent activity
        user_activity.logout_time = datetime.utcnow()
        user_activity.session_duration = (user_activity.logout_time - user_activity.login_time).seconds
        db.session.commit()
    else:
        flash('No active session found to log out.', 'danger')

    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash('Only admins can perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    user_to_update = User.query.get(user_id)
    if not user_to_update:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    form = AdminPasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            # Mark the user as inactive
            user_to_update.status = 'Inactive'
            db.session.commit()

            # If the user is logged in, forcefully log them out by invalidating the session
            if user_to_update.id == current_user.id:
                flash('Your account has been marked as inactive. You have been logged out.', 'warning')
                logout_user()  # Log out the current user immediately

            flash(f'User {user_to_update.username} has been marked as inactive.', 'success')

            # Instead of redirecting to login, redirect back to the dashboard or another page
            return redirect(url_for('dashboard'))

        else:
            flash('Incorrect password. Please try again.', 'danger')

    return render_template('auth/delete_user_confirmation.html', user=user_to_update, form=form)



#Add a new route to reactivate users
@app.route('/reactivate_user/<int:user_id>', methods=['POST'])
@login_required
def reactivate_user(user_id):
    if not current_user.is_admin():
        flash('Only admins can perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    user_to_update = User.query.get(user_id)
    if not user_to_update:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    user_to_update.status = 'Active'
    db.session.commit()
    flash(f'User {user_to_update.username} has been reactivated.', 'success')
    return redirect(url_for('dashboard'))



@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the current user is either an admin or a staff member resetting a member's password
    if not (current_user.is_admin() or (current_user.is_staff() and user.role == 'Member')):
        flash('You do not have permission to reset this user\'s password.', 'danger')
        return redirect(url_for('dashboard'))

    new_password = None  # To store the generated password, if needed

    if request.method == 'POST':
        # Generate a new random password
        new_password = generate_random_password(10)  # Random password of length 10
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        user.password = hashed_password
        db.session.commit()

        # Show the new password to the admin or the user (in case it's their own password)
        flash(f'Password has been reset successfully. New password: {new_password}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('auth/reset_password.html', user=user, new_password=new_password)


def generate_random_password(length=8):
    """Generate a random password with letters and digits."""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected for upload', 'danger')
        return redirect(url_for('dashboard', tab='profile-settings'))  # Redirect to the profile settings tab

    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('dashboard', tab='profile-settings'))  # Redirect to the profile settings tab

    if allowed_file(file.filename):
        # Save the file and generate the image filename
        picture_filename = save_profile_picture(file)
        current_user.profile_picture = picture_filename
        db.session.commit()

        flash('Your profile picture has been updated!', 'success')
        return redirect(url_for('dashboard', tab='profile-settings'))  # Redirect to the profile settings tab

    flash('File not allowed. Please upload an image file (jpg, png, jpeg).', 'danger')
    return redirect(url_for('dashboard', tab='profile-settings'))  # Redirect to the profile settings tab

# *************** Profile Module End ***************





# Connection ////////////////////

from flask import jsonify, render_template, request, url_for, redirect, flash
from datetime import datetime
from sqlalchemy import or_, and_

# Update the Connection model to include these methods
class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    requester = db.relationship('User', foreign_keys=[requester_id], backref='sent_requests')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_requests')

    def __init__(self, requester_id, recipient_id):
        self.requester_id = requester_id
        self.recipient_id = recipient_id

    @staticmethod
    def get_connection(user1_id, user2_id):
        """Get existing connection between two users regardless of who sent the request"""
        return Connection.query.filter(
            or_(
                and_(Connection.requester_id == user1_id, Connection.recipient_id == user2_id),
                and_(Connection.requester_id == user2_id, Connection.recipient_id == user1_id)
            )
        ).first()

    def can_manage_request(self, user_id):
        """Check if user can manage this connection request"""
        if self.status == 'pending':
            if user_id == self.recipient_id:  # Recipient can accept/reject
                return True
            if user_id == self.requester_id:  # Requester can cancel
                return True
        elif self.status == 'accepted':
            # Both users can remove the connection
            if user_id in [self.recipient_id, self.requester_id]:
                return True
        return False

# Add new route for removing connections
@app.route('/remove_connection/<int:connection_id>', methods=['POST'])
@login_required
def remove_connection(connection_id):
    try:
        connection = Connection.query.get_or_404(connection_id)
        
        # Verify that the current user is part of the connection
        if current_user.id not in [connection.requester_id, connection.recipient_id]:
            return jsonify({
                'status': 'error',
                'message': 'You are not authorized to remove this connection.'
            }), 403

        # Only accepted connections can be removed
        if connection.status != 'accepted':
            return jsonify({
                'status': 'error',
                'message': 'Only accepted connections can be removed.'
            }), 400

        # Delete the connection
        db.session.delete(connection)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Connection removed successfully.'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in remove_connection: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while removing the connection.'
        }), 500


@app.route('/community')
@login_required
def community():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Number of users per page
        search_query = request.args.get('search', '').strip()
        
        # Base query excluding current user and inactive users
        query = User.query.filter(
            User.id != current_user.id,
            User.status == 'Active'
        )

        # Apply search filter if provided
        if search_query:
            query = query.filter(
                or_(
                    User.username.ilike(f'%{search_query}%'),
                    User.email.ilike(f'%{search_query}%')
                )
            )

        # Paginate results
        users = query.paginate(page=page, per_page=per_page, error_out=False)

        # Get all connection statuses for current user
        connections = Connection.query.filter(
            or_(
                Connection.requester_id == current_user.id,
                Connection.recipient_id == current_user.id
            )
        ).all()

        # Create dictionaries for connection statuses
        sent_requests = {
            conn.recipient_id: conn for conn in connections 
            if conn.requester_id == current_user.id
        }
        received_requests = {
            conn.requester_id: conn for conn in connections 
            if conn.recipient_id == current_user.id
        }

        return render_template(
            'community/community.html',
            users=users,
            sent_requests=sent_requests,
            received_requests=received_requests,
            search_query=search_query
        )
    except Exception as e:
        app.logger.error(f"Error in community route: {str(e)}")
        flash('An error occurred while loading the community page.', 'danger')
        return redirect(url_for('dashboard'))



# Update the send_request route to handle rejected connections
@app.route('/send_request/<int:recipient_id>', methods=['POST'])
@login_required
def send_request(recipient_id):
    try:
        # Validate recipient exists and is active
        recipient = User.query.filter_by(id=recipient_id, status='Active').first()
        if not recipient:
            return jsonify({
                'status': 'error',
                'message': 'User not found or is inactive.'
            }), 404

        # Check if trying to connect with self
        if recipient_id == current_user.id:
            return jsonify({
                'status': 'error',
                'message': 'You cannot connect with yourself.'
            }), 400

        # Check existing connection
        existing_connection = Connection.get_connection(current_user.id, recipient_id)

        if existing_connection:
            # If connection exists and is rejected, allow new request from either user
            if existing_connection.status == 'rejected':
                db.session.delete(existing_connection)
                db.session.commit()
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Connection already exists with status: {existing_connection.status}'
                }), 400

        # Create new connection
        connection = Connection(requester_id=current_user.id, recipient_id=recipient_id)
        db.session.add(connection)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': f'Connection request sent to {recipient.username}.',
            'connection_id': connection.id
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in send_request: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while sending the request.'
        }), 500

@app.route('/cancel_request/<int:connection_id>', methods=['POST'])
@login_required
def cancel_request(connection_id):
    try:
        connection = Connection.query.get_or_404(connection_id)
        
        # Verify that the current user is the requester
        if connection.requester_id != current_user.id:
            return jsonify({
                'status': 'error',
                'message': 'You can only cancel your own requests.'
            }), 403

        # Verify that the request is still pending
        if connection.status != 'pending':
            return jsonify({
                'status': 'error',
                'message': 'Only pending requests can be cancelled.'
            }), 400

        # Delete the connection request
        db.session.delete(connection)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Connection request cancelled successfully.'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in cancel_request: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while cancelling the request.'
        }), 500




@app.route('/manage_request/<int:connection_id>/<string:action>', methods=['POST'])
@login_required
def manage_request(connection_id, action):
    try:
        connection = Connection.query.get_or_404(connection_id)
        
        if not connection.can_manage_request(current_user.id):
            return jsonify({
                'status': 'error',
                'message': 'You are not authorized to manage this request.'
            }), 403

        if action not in ['accept', 'reject', 'cancel']:
            return jsonify({
                'status': 'error',
                'message': 'Invalid action specified.'
            }), 400

        if action == 'accept' and connection.recipient_id == current_user.id:
            connection.status = 'accepted'
            message = 'Connection request accepted.'
        elif action == 'reject' and connection.recipient_id == current_user.id:
            connection.status = 'rejected'
            message = 'Connection request rejected.'
        elif action == 'cancel' and connection.requester_id == current_user.id:
            db.session.delete(connection)
            message = 'Connection request cancelled.'
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid action for your role.'
            }), 403

        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': message
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in manage_request: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while processing the request.'
        }), 500

@app.route('/my_connections')
@login_required
def my_connections():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20

        # Get all connections for the current user
        connections_query = Connection.query.filter(
            or_(
                Connection.requester_id == current_user.id,
                Connection.recipient_id == current_user.id
            )
        )

        # Filter by status if provided
        status_filter = request.args.get('status', 'all')
        if status_filter != 'all':
            connections_query = connections_query.filter(Connection.status == status_filter)

        # Sort by most recent first
        connections_query = connections_query.order_by(Connection.updated_at.desc())

        # Paginate results
        connections = connections_query.paginate(page=page, per_page=per_page, error_out=False)

        return render_template(
            'community/my_connections.html',
            connections=connections,
            current_filter=status_filter
        )
    except Exception as e:
        app.logger.error(f"Error in my_connections: {str(e)}")
        flash('An error occurred while loading your connections.', 'danger')
        return redirect(url_for('dashboard'))


# Connection end //////////////////////////



# *************** Blog Module ***************

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, published, archived
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('blog_posts', lazy=True))
    featured_image = db.Column(db.String(255), nullable=True)  # Path to the image file

class BlogForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=5, max=200)])
    content = StringField('Content', validators=[DataRequired()])
    featured_image = FileField('Featured Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Submit for Review')


# Blog routes to app.py
@app.route('/blogs')
def blogs():
    page = request.args.get('page', 1, type=int)
    posts = BlogPost.query.filter_by(status='published').order_by(BlogPost.created_at.desc()).paginate(page=page, per_page=5)
    return render_template('blog/blogs.html', posts=posts)


@app.route('/blog/new', methods=['GET', 'POST'])
@login_required
def new_blog():
    form = BlogForm()
    if form.validate_on_submit():
        # Fetch form data
        title = form.title.data
        content = form.content.data

        filename = None
        if form.featured_image.data:
            image_file = form.featured_image.data
            
            # Generate a unique filename using UUID
            original_filename = secure_filename(image_file.filename)
            ext = os.path.splitext(original_filename)[1]  # Get the file extension
            unique_filename = f"{uuid.uuid4().hex}{ext}"  # Generate unique name
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Open the uploaded image and optimize it
            with Image.open(image_file) as img:
                max_size = (900, 600)  # Resize the image to fit within 800x800 pixels
                img = ImageOps.exif_transpose(img)  # Handle orientation from EXIF metadata
                img.thumbnail(max_size, Image.Resampling.LANCZOS)  # Use LANCZOS resampling
                img.save(filepath, optimize=True, quality=85)  # Save with optimization
            
            filename = unique_filename

        # Create a new blog post
        post = BlogPost(
            title=title,
            content=content,
            author=current_user,
            featured_image=filename
        )

        # Save the post to the database
        db.session.add(post)
        db.session.commit()

        flash('Blog post submitted for review.', 'success')
        return redirect(url_for('blogs'))
    return render_template('blog/create_blog.html', form=form)


@app.route('/blog/<int:post_id>')
def view_blog(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.status != 'published' and post.author != current_user and not current_user.is_staff() and not current_user.is_admin():
        abort(403)
    return render_template('blog/view_blog.html', post=post)


@app.route('/blog/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_blog(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
        
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        post.status = 'pending'
        db.session.commit()
        flash('Blog post updated and submitted for review.', 'success')
        return redirect(url_for('my_blogs'))
        
    return render_template('blog/edit_blog.html', post=post)


@app.route('/blog/<int:post_id>/archive', methods=['POST'])
@login_required
def archive_blog(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
        
    post.status = 'archived'
    db.session.commit()
    flash('Blog post archived.', 'success')
    return redirect(url_for('my_blogs'))


@app.route('/my-blogs')
@login_required
def my_blogs():
    posts = BlogPost.query.filter_by(author=current_user).order_by(BlogPost.created_at.desc()).all()
    return render_template('blog/my_blogs.html', posts=posts)


@app.route('/blog/review')
@login_required
def review_blogs():
    if not current_user.is_staff() and not current_user.is_admin():
        abort(403)
    posts = BlogPost.query.filter_by(status='pending').order_by(BlogPost.created_at.desc()).all()
    return render_template('blog/review_blogs.html', posts=posts)


@app.route('/blog/<int:post_id>/review', methods=['POST'])
@login_required
def review_blog(post_id):
    if not current_user.is_staff() and not current_user.is_admin():
        abort(403)
        
    post = BlogPost.query.get_or_404(post_id)
    action = request.form.get('action')
    
    if action == 'approve':
        post.status = 'published'
        flash('Blog post approved and published.', 'success')
    elif action == 'reject':
        post.status = 'pending'
        flash('Blog post rejected.', 'warning')
        
    db.session.commit()
    return redirect(url_for('review_blogs'))

# *************** Blog Module End ***************





# *************** Job Module ***************

# models.py (add to existing file)
class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    salary_range = db.Column(db.String(100))
    job_type = db.Column(db.String(50), nullable=False)  # Full-time, Part-time, Contract
    status = db.Column(db.String(50), default='Pending')  # Pending, Approved, Rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('jobs', lazy=True))

# Job forms.py (create new or add to existing)
class JobForm(FlaskForm):
    title = StringField('Job Title', validators=[DataRequired(), Length(min=3, max=200)])
    company = StringField('Company Name', validators=[DataRequired(), Length(min=2, max=200)])
    location = StringField('Location', validators=[DataRequired(), Length(min=2, max=200)])
    description = StringField('Job Description', validators=[DataRequired()])
    requirements = StringField('Job Requirements', validators=[DataRequired()])
    salary_range = StringField('Salary Range')
    job_type = SelectField('Job Type', choices=[
        ('Full-time', 'Full-time'),
        ('Part-time', 'Part-time'),
        ('Contract', 'Contract')
    ], validators=[DataRequired()])
    submit = SubmitField('Post Job')



# Job routes.py (add to existing file)
@app.route('/jobs')
def jobs_list():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'Approved')
    
    # For admin/staff, show all jobs with status filter
    if current_user.is_authenticated and (current_user.is_admin() or current_user.is_staff()):
        jobs = Job.query.filter_by(status=status_filter).order_by(Job.created_at.desc())
    else:
        # For regular users and visitors, show only approved jobs
        jobs = Job.query.filter_by(status='Approved').order_by(Job.created_at.desc())
    
    jobs = jobs.paginate(page=page, per_page=10)
    return render_template('jobs/list.html', jobs=jobs)

@app.route('/jobs/create', methods=['GET', 'POST'])
@login_required
def create_job():
    form = JobForm()
    if form.validate_on_submit():
        job = Job(
            title=form.title.data,
            company=form.company.data,
            location=form.location.data,
            description=form.description.data,
            requirements=form.requirements.data,
            salary_range=form.salary_range.data,
            job_type=form.job_type.data,
            user_id=current_user.id,
            status='Pending'
        )
        db.session.add(job)
        db.session.commit()
        flash('Job posting submitted for review!', 'success')
        return redirect(url_for('jobs_list'))
    return render_template('jobs/create.html', form=form)

@app.route('/jobs/<int:job_id>')
def view_job(job_id):
    job = Job.query.get_or_404(job_id)
    if job.status != 'Approved' and not (current_user.is_authenticated and 
        (current_user.is_admin() or current_user.is_staff() or current_user.id == job.user_id)):
        abort(404)
    return render_template('jobs/view.html', job=job)

@app.route('/jobs/<int:job_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = Job.query.get_or_404(job_id)
    if not (current_user.is_admin() or current_user.is_staff() or current_user.id == job.user_id):
        abort(403)
    
    form = JobForm()
    if form.validate_on_submit():
        job.title = form.title.data
        job.company = form.company.data
        job.location = form.location.data
        job.description = form.description.data
        job.requirements = form.requirements.data
        job.salary_range = form.salary_range.data
        job.job_type = form.job_type.data
        job.status = 'Pending'  # Reset to pending when edited
        db.session.commit()
        flash('Job posting updated and submitted for review!', 'success')
        return redirect(url_for('view_job', job_id=job.id))
    
    elif request.method == 'GET':
        form.title.data = job.title
        form.company.data = job.company
        form.location.data = job.location
        form.description.data = job.description
        form.requirements.data = job.requirements
        form.salary_range.data = job.salary_range
        form.job_type.data = job.job_type
    
    return render_template('jobs/edit.html', form=form, job=job)

@app.route('/jobs/<int:job_id>/review', methods=['POST'])
@login_required
def review_job(job_id):
    if not (current_user.is_admin() or current_user.is_staff()):
        abort(403)
    
    job = Job.query.get_or_404(job_id)
    action = request.form.get('action')
    
    if action == 'approve':
        job.status = 'Approved'
        flash('Job posting approved!', 'success')
    elif action == 'reject':
        job.status = 'Rejected'
        flash('Job posting rejected!', 'danger')
    
    db.session.commit()
    return redirect(url_for('jobs_list'))

@app.route('/my-jobs')
@login_required
def my_jobs():
    jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).all()
    return render_template('jobs/my_jobs.html', jobs=jobs)

# *************** Job Management Feature End ***************




# *************** onboarding Feature  ***************
# *************** Models ***************
class CustomerOnboarding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_link = db.Column(db.String(200), unique=True, nullable=False)
    customer_number = db.Column(db.String(20), unique=True, nullable=False)
    fullname = db.Column(db.String(200))
    mobile_number = db.Column(db.String(20))
    email = db.Column(db.String(120))
    contract_start_date = db.Column(db.Date)
    contract_end_date = db.Column(db.Date)
    status = db.Column(db.String(20), default='pending')  # pending, completed, expired
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    link_expiry = db.Column(db.DateTime, nullable=False)

    # New fields
    aadhaar_number = db.Column(db.String(20), unique=True)
    pan_number = db.Column(db.String(20), unique=True)
    gender = db.Column(db.String(10))
    date_of_birth = db.Column(db.Date)
    age = db.Column(db.Integer)
    nationality = db.Column(db.String(50))
    blood_group = db.Column(db.String(5))
    alternative_mobile_number = db.Column(db.String(20))
    
    # Permanent Address Fields
    permanent_address_line1 = db.Column(db.String(200))
    permanent_address_line2 = db.Column(db.String(200))
    permanent_city = db.Column(db.String(100))
    permanent_state = db.Column(db.String(100))
    permanent_country = db.Column(db.String(100))
    permanent_pincode = db.Column(db.String(20))

    # Company Details
    company_name = db.Column(db.String(200))
    company_website = db.Column(db.String(200))
    work_email = db.Column(db.String(120))
    business_category = db.Column(db.String(50))
    udyam_cin = db.Column(db.String(50))
    gstin_uin = db.Column(db.String(50))

    # Company Address Fields
    company_address_line1 = db.Column(db.String(200))
    company_address_line2 = db.Column(db.String(200))
    company_city = db.Column(db.String(100))
    company_state = db.Column(db.String(100))
    company_country = db.Column(db.String(100))
    company_pincode = db.Column(db.String(20))

    # Membership Details
    membership_type = db.Column(db.String(50))
    seats_quantity = db.Column(db.Integer)

     # contract
    agreement_doc_number = db.Column(db.String(100))
    referral_source = db.Column(db.String(50))
    community_manager = db.Column(db.String(50))
    deposit_date = db.Column(db.Date)
    deposit_amount = db.Column(db.Integer)
    rent_date = db.Column(db.Date)
    rent_amount = db.Column(db.Integer)
    notes = db.Column(db.Text)

    def calculate_age(self):
        """Calculate age based on date of birth"""
        if self.date_of_birth:
            today = datetime.today()
            return today.year - self.date_of_birth.year - (
                (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None

    def __init__(self, created_by, expires_in_days=7, mobile_number=None):
        super().__init__()
        self.created_by = created_by
        self.mobile_number = mobile_number
        self.unique_link = generate_secure_link_token()
        self.customer_number = self.generate_customer_number()
        self.link_expiry = datetime.utcnow() + timedelta(days=expires_in_days)

    def generate_customer_number(self):
        date_code = datetime.utcnow().strftime('%y%m%d')  # Format YYMMDD
        latest = CustomerOnboarding.query.order_by(CustomerOnboarding.id.desc()).first()
        last_counter = int(latest.customer_number[-4:]) if latest else 999
        return f"CZ{date_code}{last_counter + 1:04d}"




# *************** Link Security ***************
def generate_secure_link_token(length=16):
    """Generate a shortened secure link token."""
    # Generate a random token of the desired length
    random_token = secrets.token_urlsafe(length)[:length]  # Truncate to enforce fixed length
    
    # Generate an HMAC signature and truncate it to 8 characters
    signature = hmac.new(app.config['SECRET_KEY'].encode(), random_token.encode(), hashlib.sha256).hexdigest()[:8]
    
    # Return the token with the signature
    return f"{random_token}.{signature}"


def verify_secure_link_token(token):
    """Verify the integrity of a secure link token."""
    try:
        # Split the token into random_token and signature
        random_token, signature = token.rsplit('.', 1)
        
        # Recalculate the expected signature
        expected_signature = hmac.new(app.config['SECRET_KEY'].encode(), random_token.encode(), hashlib.sha256).hexdigest()[:8]
        
        # Use compare_digest to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)
    except ValueError:
        # Return False if the token format is invalid
        return False





# *************** Forms ***************
class GenerateLinkForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=200)])
    mobile_number = StringField(
        'Mobile Number',
        validators=[
            DataRequired(),
            Length(min=10, max=20),
            Regexp(
                r'^[+]?[0-9]+(?:[-\s][0-9]+)*$',
                message="Mobile number can include digits, spaces, dashes, and a leading '+'."
            )
            ]
        )
    expires_in_days = SelectField(
        'Link Expires In', choices=[(7, '7 Days'), (14, '14 Days'), (30, '30 Days')], coerce=int, default=7)
    submit = SubmitField('Generate Link')


class CustomerOnboardingForm(FlaskForm):
    # Basic Information
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=200)])
    email = StringField('Personal Email', validators=[DataRequired(), Email()])
    mobile_number = StringField(
        'Mobile Number',
        validators=[
            DataRequired(),
            Length(min=10, max=20),
            Regexp(
                r'^[+]?[0-9]+(?:[-\s][0-9]+)*$',
                message="Mobile number can include digits, spaces, dashes, and a leading '+'."
            )
            ]
        )

    alternative_mobile_number = StringField('Alternative Mobile Number', validators=[Optional(), Length(min=10, max=20)])
    
    # Identification Details
    aadhaar_number = StringField('Aadhaar Number', validators=[Optional(), Length(min=12, max=12)])
    pan_number = StringField('PAN Number', validators=[Optional(), Length(min=10, max=10)])
    
    # Personal Details
    gender = SelectField('Gender', choices=[
        ('', 'Select Gender'), 
        ('male', 'Male'), 
        ('female', 'Female'), 
        ('other', 'Other')
    ], validators=[Optional()])
    
    date_of_birth = DateField('Date of Birth', validators=[Optional()])
    age = IntegerField('Age', render_kw={'readonly': True}, validators=[Optional()])
    nationality = StringField('Nationality', validators=[Optional()])
    blood_group = SelectField('Blood Group', choices=[
        ('', 'Select Blood Group'),
        ('A+', 'A+'), ('A-', 'A-'),
        ('B+', 'B+'), ('B-', 'B-'),
        ('O+', 'O+'), ('O-', 'O-'),
        ('AB+', 'AB+'), ('AB-', 'AB-')
    ], validators=[Optional()])

    # Permanent Address
    permanent_address_line1 = StringField('Permanent Address Line 1', validators=[Optional()])
    permanent_address_line2 = StringField('Permanent Address Line 2', validators=[Optional()])
    permanent_city = StringField('City', validators=[Optional()])
    permanent_state = StringField('State', validators=[Optional()])
    permanent_country = StringField('Country', validators=[Optional()])
    permanent_pincode = StringField('Pin Code', validators=[Optional(), Length(min=6, max=6)])

    # Company Details
    company_name = StringField('Company Name', validators=[Optional()])
    company_website = StringField('Company Website', validators=[Optional(), URL()])
    work_email = StringField('Work Email', validators=[Optional(), Email()])
    business_category = SelectField('Business Category', choices=[
        ('', 'Select Business Category'),
        ('digital_marketing', 'Digital Marketing'),
        ('engineering', 'Engineering')
    ], validators=[Optional()])
    udyam_cin = StringField('Udyam / CIN', validators=[Optional()])
    gstin_uin = StringField('GSTIN / UIN', validators=[Optional()])

    # Company Address
    company_address_line1 = StringField('Company Address Line 1', validators=[Optional()])
    company_address_line2 = StringField('Company Address Line 2', validators=[Optional()])
    company_city = StringField('Company City', validators=[Optional()])
    company_state = StringField('Company State', validators=[Optional()])
    company_country = StringField('Company Country', validators=[Optional()])
    company_pincode = StringField('Company Pin Code', validators=[Optional(), Length(min=6, max=6)])

    # Membership Details
    membership_type = SelectField('Membership Type', choices=[
        ('', 'Select Membership Type'),
        ('shared_space_ac', 'Shared Space AC'),
        ('shared_space_non_ac', 'Shared Space Non AC')
    ], validators=[Optional()])
    seats_quantity = IntegerField('Seats Quantity', validators=[Optional(), NumberRange(min=1)])

    submit = SubmitField('Submit')




class ContractDatesForm(FlaskForm):
    # Existing Contract Date Fields
    contract_start_date = DateField('Contract Start Date', validators=[DataRequired()])
    contract_end_date = DateField('Contract End Date', validators=[DataRequired()])
    
    # Agreement and Membership Details
    agreement_doc_number = StringField('Agreement Doc. No.', validators=[Optional()])
    membership_type = SelectField('Membership Type', choices=[
        ('', 'Select Membership Type'),
        ('shared_space_ac', 'Shared Space AC'),
        ('shared_space_non_ac', 'Shared Space Non AC')
    ], validators=[Optional()])
    seats_quantity = IntegerField('Seats Quantity', validators=[Optional(), NumberRange(min=1)])
    
    # Referral and Management
    referral_source = SelectField('Referral Source', choices=[
        ('', 'Select Referral Source'),
        ('direct_mail', 'Direct Mail'),
        ('cold_call', 'Cold Call')
    ], validators=[Optional()])
    community_manager = SelectField('Community Manager', choices=[
        ('', 'Select Community Manager'),
        ('soumila', 'Soumila'),
        ('suloch', 'Suloch')
    ], validators=[Optional()])
    
    # Financial Details
    deposit_date = DateField('Deposit Date', validators=[Optional()])
    deposit_amount = IntegerField('Deposit Amount (INR)', validators=[Optional(), NumberRange(min=0)])
    rent_date = DateField('Rent Date', validators=[Optional()])
    rent_amount = IntegerField('Rent Amount (INR)', validators=[Optional(), NumberRange(min=0)])
    
    # Additional Notes
    notes = TextAreaField('Notes', validators=[Optional()])
    
    submit = SubmitField('Update Contract Details')




#  -------------------
# *************** Routes ***************
@app.route('/generate_customer_link', methods=['GET', 'POST'])
@login_required
def generate_customer_link():
    if not current_user.is_staff() and not current_user.is_admin():
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('dashboard'))

    form = GenerateLinkForm()
    if form.validate_on_submit():
        onboarding = CustomerOnboarding(
            created_by=current_user.id,
            expires_in_days=form.expires_in_days.data,
            mobile_number=form.mobile_number.data
        )
        onboarding.fullname = form.fullname.data
        onboarding.status = 'link generated'
        db.session.add(onboarding)
        db.session.commit()

        # Include customer_number in the link
        onboarding_link = url_for('customer_onboarding',
                                  unique_link=f"{onboarding.customer_number}-{onboarding.unique_link}",
                                  _external=True)

        flash(f'Customer onboarding link generated successfully! Customer Number: {onboarding.customer_number}', 'success')
        return render_template('onboarding/link_generated.html',
                               onboarding_link=onboarding_link,
                               customer_number=onboarding.customer_number)

    return render_template('onboarding/generate_link.html', form=form)



@app.route('/customer-onboarding/<unique_link>', methods=['GET', 'POST'])
def customer_onboarding(unique_link):
    try:
        customer_number, token = unique_link.split('-', 1)
    except ValueError:
        abort(403, description="Invalid or tampered link.")

    # Verify the token
    if not verify_secure_link_token(token):
        abort(403, description="Invalid or tampered link.")

    onboarding = CustomerOnboarding.query.filter_by(customer_number=customer_number, unique_link=token).first_or_404()

    # Handle expired or completed links
    if onboarding.status in ['Pending Contract Update', 'completed']:
        return render_template('onboarding/link_expired.html', onboarding=onboarding)

    if datetime.utcnow() > onboarding.link_expiry:
        onboarding.status = 'expired'
        db.session.commit()
        return render_template('onboarding/link_expired.html', onboarding=onboarding)

    form = CustomerOnboardingForm(obj=onboarding)  # Pre-fill form with onboarding data
    
    # Handle age calculation
    if form.date_of_birth.data:
        form.age.data = (datetime.utcnow().date() - form.date_of_birth.data).days // 365

    if form.validate_on_submit():
        # Basic Information
        onboarding.fullname = form.fullname.data
        onboarding.email = form.email.data
        onboarding.mobile_number = form.mobile_number.data
        onboarding.alternative_mobile_number = form.alternative_mobile_number.data

        # Identification Details
        onboarding.aadhaar_number = form.aadhaar_number.data
        onboarding.pan_number = form.pan_number.data

        # Personal Details
        onboarding.gender = form.gender.data
        onboarding.date_of_birth = form.date_of_birth.data
        onboarding.age = onboarding.calculate_age()
        onboarding.nationality = form.nationality.data
        onboarding.blood_group = form.blood_group.data

        # Permanent Address
        onboarding.permanent_address_line1 = form.permanent_address_line1.data
        onboarding.permanent_address_line2 = form.permanent_address_line2.data
        onboarding.permanent_city = form.permanent_city.data
        onboarding.permanent_state = form.permanent_state.data
        onboarding.permanent_country = form.permanent_country.data
        onboarding.permanent_pincode = form.permanent_pincode.data

        # Company Details
        onboarding.company_name = form.company_name.data
        onboarding.company_website = form.company_website.data
        onboarding.work_email = form.work_email.data
        onboarding.business_category = form.business_category.data
        onboarding.udyam_cin = form.udyam_cin.data
        onboarding.gstin_uin = form.gstin_uin.data

        # Company Address
        onboarding.company_address_line1 = form.company_address_line1.data
        onboarding.company_address_line2 = form.company_address_line2.data
        onboarding.company_city = form.company_city.data
        onboarding.company_state = form.company_state.data
        onboarding.company_country = form.company_country.data
        onboarding.company_pincode = form.company_pincode.data

        # Membership Details
        onboarding.membership_type = form.membership_type.data
        onboarding.seats_quantity = form.seats_quantity.data

        # Update status
        onboarding.status = 'Pending Contract Update'
        onboarding.completed_at = datetime.utcnow()
        
        db.session.commit()

        flash('Thank you! Your information has been submitted successfully.', 'success')
        return render_template('onboarding/link_expired.html', onboarding=onboarding)

    return render_template('onboarding/customer_form.html', form=form, onboarding=onboarding)





@app.route('/request-new-link', methods=['POST'])
@login_required
def request_new_link():
    customer_number = request.form.get('customer_number')
    onboarding = CustomerOnboarding.query.filter_by(customer_number=customer_number).first()

    if onboarding:
        onboarding.unique_link = generate_secure_link_token()
        onboarding.link_expiry = datetime.utcnow() + timedelta(days=7)
        db.session.commit()
        flash('A new onboarding link has been generated.', 'success')
    else:
        flash('Customer not found.', 'danger')

    return redirect(url_for('manage_onboarding'))


@app.route('/manage-onboarding')
@login_required
def manage_onboarding():
    if not current_user.is_staff() and not current_user.is_admin():
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch all onboarding records
    onboardings = CustomerOnboarding.query.order_by(CustomerOnboarding.created_at.desc()).all()

    # Pass records to the template
    return render_template('onboarding/manage.html', onboardings=onboardings)




@app.route('/update-contract-dates/<int:onboarding_id>', methods=['GET', 'POST'])
@login_required
def update_contract_dates(onboarding_id):
    if not current_user.is_staff() and not current_user.is_admin():
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('dashboard'))

    onboarding = CustomerOnboarding.query.get_or_404(onboarding_id)
    form = ContractDatesForm(obj=onboarding)

    if form.validate_on_submit():
        # Update contract and membership details
        onboarding.contract_start_date = form.contract_start_date.data
        onboarding.contract_end_date = form.contract_end_date.data
        onboarding.agreement_doc_number = form.agreement_doc_number.data
        onboarding.membership_type = form.membership_type.data
        onboarding.seats_quantity = form.seats_quantity.data
        
        # Update referral and management details
        onboarding.referral_source = form.referral_source.data
        onboarding.community_manager = form.community_manager.data
        
        # Update financial details
        onboarding.deposit_date = form.deposit_date.data
        onboarding.deposit_amount = form.deposit_amount.data
        onboarding.rent_date = form.rent_date.data
        onboarding.rent_amount = form.rent_amount.data
        
        # Update notes
        onboarding.notes = form.notes.data
        
        # Update status
        onboarding.status = 'completed'
        
        db.session.commit()
        flash('Contract details updated successfully!', 'success')
        return redirect(url_for('manage_onboarding'))

    return render_template('onboarding/update_contract_dates.html', form=form, onboarding=onboarding)



@app.route('/download-onboarding-pdf/<int:onboarding_id>')
@login_required
def download_onboarding_pdf(onboarding_id):
    # Ensure the user has the correct permissions
    if not current_user.is_staff() and not current_user.is_admin():
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch the onboarding data
    onboarding = CustomerOnboarding.query.get_or_404(onboarding_id)

    # Get the current date/time for the footer
    current_time = datetime.utcnow().strftime('%B %d, %Y %H:%M:%S')

    # Render the HTML template with onboarding data
    rendered_html = render_template('onboarding/pdf_template.html', onboarding=onboarding, current_time=current_time)

    # Generate the PDF using xhtml2pdf
    pdf = generate_pdf(rendered_html)

    # Serve the PDF as a downloadable file
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Customer_{onboarding.customer_number}.pdf'
    return response

def generate_pdf(html_content):
    # Create a file-like object to store the PDF output
    pdf_file = io.BytesIO()

    # Use pisa to generate the PDF and write it to the file-like object
    pisa_status = pisa.pisaDocument(html_content.encode('UTF-8'), pdf_file)

    # Check if there was an error during the generation
    if pisa_status.err:
        raise Exception("Error generating PDF.")
    
    # Seek to the beginning of the file-like object to send it in the response
    pdf_file.seek(0)
    
    return pdf_file.read()  # Return the content of the PDF file




@app.route('/edit-onboarding/<int:onboarding_id>', methods=['GET', 'POST'])
@login_required
def edit_onboarding(onboarding_id):
    if not current_user.is_staff() and not current_user.is_admin():
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('dashboard'))

    onboarding = CustomerOnboarding.query.get_or_404(onboarding_id)
    form = CustomerOnboardingForm(obj=onboarding)

    if form.validate_on_submit():
        onboarding.fullname = form.fullname.data
        onboarding.email = form.email.data
        db.session.commit()
        flash('Onboarding information updated successfully!', 'success')
        return redirect(url_for('manage_onboarding'))

    return render_template('onboarding/edit_onboarding.html', form=form, onboarding=onboarding)

# *************** onboarding Feature End ***************





# *************** Helpdesk module start***************
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # Title should not exceed 200 characters
    description = db.Column(db.Text, nullable=False)  # Description is mandatory
    status = db.Column(db.String(20), default='Open', nullable=False)  # Status defaults to "Open"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Automatically set the creation time
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Update on change
    priority = db.Column(
        db.String(20), 
        nullable=False, 
        default='Medium', 
        server_default='Medium'  # Ensures database default value
    )  # Add default priority with validation
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who created the ticket
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Assigned user (optional)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('tickets', lazy=True))  # Creator relationship
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref=db.backref('assigned_tickets', lazy=True))  # Assigned relationship

    def __repr__(self):
        return f"<Ticket(id={self.id}, title={self.title}, priority={self.priority}, status={self.status})>"

class TicketReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    ticket = db.relationship('Ticket', backref=db.backref('replies', lazy=True))
    user = db.relationship('User', backref=db.backref('ticket_replies', lazy=True))

class TicketAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=True)
    reply_id = db.Column(db.Integer, db.ForeignKey('ticket_reply.id'), nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    ticket = db.relationship('Ticket', backref=db.backref('attachments', lazy=True))
    reply = db.relationship('TicketReply', backref=db.backref('attachments', lazy=True))
    user = db.relationship('User', backref=db.backref('ticket_attachments', lazy=True))


from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileField, FileAllowed

class CreateTicketForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(message="Title is required."),
        Length(min=3, max=200, message="Title must be between 3 and 200 characters.")
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(message="Description is required."),
        Length(min=10, max=1000, message="Description must be between 10 and 1000 characters.")
    ])
    attachments = FileField('Attachments', validators=[
        FileAllowed(['jpg', 'png', 'pdf', 'txt'], 'Invalid file type. Only images, PDFs, and text files are allowed.'),
        # Optional custom file size validator
        lambda form, field: validate_file_size(field)
    ])
    priority = SelectField(
        'Priority',
        choices=[
            ('Low', 'Low'),
            ('Medium', 'Medium'),
            ('High', 'High'),
            ('Critical', 'Critical')
        ],
        default='Medium',  # Ensure default is one of the values in `choices`
        validators=[DataRequired()]
        )
    
    submit = SubmitField('Create Ticket')

def validate_file_size(field):
    if field.data:
        file_size = len(field.data.read())
        field.data.seek(0)  # Reset file pointer
        if file_size > MAX_FILE_SIZE:
            raise ValidationError(f'File must be less than {MAX_FILE_SIZE / (1024*1024)}MB')

class ReplyTicketForm(FlaskForm):
    message = TextAreaField('Reply', validators=[DataRequired(), Length(min=3)])
    attachments = FileField('Attachments', validators=[
        FileAllowed(['jpg', 'png', 'pdf', 'txt'], 'Only image, PDF, and text files are allowed.')
    ])
    submit = SubmitField('Send Reply')

class AssignTicketForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('Open', 'Open'), 
        ('Closed', 'Closed'), 
        ('Reopened', 'Reopened')
    ])
    assigned_to = SelectField('Assign To', coerce=int)
    submit = SubmitField('Update Ticket')

import os
from werkzeug.utils import secure_filename
from sqlalchemy import or_
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


@app.route('/helpdesk/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    form = CreateTicketForm()
    if form.validate_on_submit():
        try:
            # File size validation
            if form.attachments.data:
                file = form.attachments.data
                if len(file.read()) > MAX_FILE_SIZE:
                    file.seek(0)  # Reset file pointer
                    flash('File size must be less than 10MB', 'danger')
                    return render_template('helpdesk/create_ticket.html', form=form)
                file.seek(0)  # Reset file pointer

            ticket = Ticket(
                title=form.title.data,
                description=form.description.data,
                user=current_user,
                priority=form.priority.data  # Save priority
            )
            db.session.add(ticket)
            db.session.flush()

            # Handle file upload
            if form.attachments.data:
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)

                attachment = TicketAttachment(
                    ticket_id=ticket.id,
                    filename=filename,
                    filepath=filepath,
                    user=current_user
                )
                db.session.add(attachment)

            db.session.commit()
            flash('Ticket created successfully!', 'success')
            return redirect(url_for('view_tickets'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Ticket creation error: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')

    return render_template('helpdesk/create_ticket.html', form=form)

@app.route('/helpdesk/tickets', methods=['GET'])
@login_required
def view_tickets():
    # Search and filter parameters
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    sort = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')

    # Base query
    query = Ticket.query

    # Role-based filtering
    if not (current_user.is_admin() or current_user.is_staff()):
        query = query.filter_by(user=current_user)

    # Search filter
    if search_query:
        query = query.filter(
            or_(
                Ticket.title.ilike(f'%{search_query}%'),
                Ticket.description.ilike(f'%{search_query}%')
            )
        )

    # Status filter
    if status_filter:
        query = query.filter_by(status=status_filter)

    # Sorting
    if order == 'desc':
        query = query.order_by(getattr(Ticket, sort).desc())
    else:
        query = query.order_by(getattr(Ticket, sort).asc())

    tickets = query.all()
    
    # Available statuses for filter dropdown
    statuses = ['Open', 'Closed', 'Reopened']

    return render_template('helpdesk/view_tickets.html', 
                           tickets=tickets, 
                           statuses=statuses,
                           search_query=search_query,
                           status_filter=status_filter,
                           sort=sort,
                           order=order)

@app.route('/helpdesk/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_details(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check permissions
    if not (current_user.is_admin() or current_user.is_staff() or ticket.user == current_user):
        flash('Unauthorized access', 'danger')
        return redirect(url_for('view_tickets'))

    reply_form = ReplyTicketForm()
    assign_form = AssignTicketForm()
    
    if ticket.status == 'Closed' and reply_form.validate_on_submit():
        ticket.status = 'Reopened'
        db.session.commit()
        flash('Ticket has been reopened due to a new reply!', 'info')


    # Populate assignable users for staff/admin
    if current_user.is_admin() or current_user.is_staff():
        staff_users = User.query.filter(
            or_(User.role == 'Staff', User.role == 'Admin')
        ).all()
        assign_form.assigned_to.choices = [(user.id, user.username) for user in staff_users]
        
        if assign_form.validate_on_submit():
            ticket.status = assign_form.status.data
            ticket.assigned_to_id = assign_form.assigned_to.data
            db.session.commit()
            flash('Ticket updated successfully!', 'success')
            return redirect(url_for('ticket_details', ticket_id=ticket.id))

    if reply_form.validate_on_submit():
        reply = TicketReply(
            ticket=ticket,
            user=current_user,
            message=reply_form.message.data
        )
        db.session.add(reply)
        db.session.flush()

        # Handle file upload for reply
        if reply_form.attachments.data:
            file = reply_form.attachments.data
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            attachment = TicketAttachment(
                reply_id=reply.id,
                filename=filename,
                filepath=filepath,
                user=current_user
            )
            db.session.add(attachment)

        db.session.commit()
        flash('Reply sent successfully!', 'success')
        return redirect(url_for('ticket_details', ticket_id=ticket.id))

    return render_template('helpdesk/ticket_details.html', 
                           ticket=ticket, 
                           reply_form=reply_form, 
                           assign_form=assign_form)


@app.route('/download/attachment/<int:attachment_id>')
@login_required
def download_attachment(attachment_id):
    attachment = TicketAttachment.query.get_or_404(attachment_id)
    
    # Permissions check
    if not (current_user == attachment.user or 
            current_user.is_staff() or 
            current_user.is_admin()):
        flash('Unauthorized access', 'danger')
        return redirect(url_for('view_tickets'))

    # Ensure the file exists
    if not os.path.exists(attachment.filepath):
        flash('File not found', 'danger')
        return redirect(url_for('view_tickets'))

    # Serve the file for download
    return send_file(attachment.filepath, as_attachment=True)

@app.route('/helpdesk/reopen/<int:ticket_id>', methods=['POST'])
@login_required
def reopen_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check permissions (only admin or ticket creator can reopen)
    if not (current_user.is_admin() or ticket.user == current_user):
        flash('Unauthorized access', 'danger')
        return redirect(url_for('view_tickets'))

    # Reopen the ticket
    ticket.status = 'Reopened'
    db.session.commit()
    flash('Ticket has been reopened!', 'success')
    return redirect(url_for('ticket_details', ticket_id=ticket.id))


# *************** Helpdesk module end ***************



@app.errorhandler(404)
def page_not_found(e):
    return render_template('error/error_404.html'), 404

# Main block
if __name__ == '__main__':
    app.run(debug=True)