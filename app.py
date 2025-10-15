import os
import requests
from flask import Flask, render_template, jsonify, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateTimeField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-secret")
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'user.data')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

registrations = db.Table('registrations',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('match_id', db.Integer, db.ForeignKey('match.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    matches = db.relationship('Match', secondary=registrations, backref=db.backref('participants', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)

class MatchForm(FlaskForm):
    start_time = DateTimeField('Start Time (YYYY-MM-DD HH:MM:SS)', format='%Y-%m-%d %H:%M:%S', validators=[DataRequired()])
    submit = SubmitField('Create Match')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# ---------------- Web 路由 ----------------
@app.get("/")
def index():
    return render_template("index.html")

@app.route('/stats')
@login_required
def get_stats():
    try:
        response = requests.get(f'https://generals.io/api/replaysForUsername?u={current_user.username}&offset=0&count=200')
        response.raise_for_status()
        replays = response.json()

        wins = 0
        loses = 0

        for replay in replays:
            if replay.get('type') == 'custom':
                ranking = replay.get('ranking', [])
                if ranking and ranking[0].get('name') == current_user.username:
                    wins += 1
                else:
                    loses += 1

        return jsonify({'wins': wins, 'loses': loses})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if not current_user.is_admin:
        flash("You don't have permission to access this page.")
        return redirect(url_for('index'))
    form = MatchForm()
    if form.validate_on_submit():
        match = Match(start_time=form.start_time.data)
        db.session.add(match)
        db.session.commit()
        flash('Match created successfully!')
        return redirect(url_for('events'))
    return render_template('create.html', form=form)

@app.route('/events')
def events():
    matches = Match.query.all()
    return render_template('events.html', matches=matches)

@app.route('/signup/<int:match_id>', methods=['POST'])
@login_required
def signup(match_id):
    match = Match.query.get_or_404(match_id)
    if current_user in match.participants:
        flash('You are already signed up for this match.')
    else:
        match.participants.append(current_user)
        db.session.commit()
        flash('You have successfully signed up for the match.')
    return redirect(url_for('events'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

def force_init_db():
    """
    强制删除所有表并重新创建它们，然后创建一个管理员用户。
    仅用于开发环境。
    """
    print("强制初始化数据库...")
    db.drop_all()
    db.create_all()

    # 创建管理员用户 mashiro
    if not User.query.filter_by(username='mashiro').first():
        print("创建管理员用户 'mashiro'...")
        admin_user = User(username='mashiro', is_admin=True)
        admin_user.set_password('mashiro')
        db.session.add(admin_user)
        print("管理员用户 'mashiro' 创建成功。")

    # 创建管理员用户 DDHope
    if not User.query.filter_by(username='DDHope').first():
        print("创建管理员用户 'DDHope'...")
        admin_user2 = User(username='DDHope', is_admin=True)
        admin_user2.set_password('DDHope')
        db.session.add(admin_user2)
        print("管理员用户 'DDHope' 创建成功。")

    db.session.commit()
    print("数据库初始化完成。")


if __name__ == "__main__":
    with app.app_context():
        force_init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
