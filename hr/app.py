from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import eveapi
from prest import Prest

from hr.shared import db
from hr.models import User, Member, APIKey
from hr.reddit_oauth import RedditOAuth


app = Flask(__name__)
app.config.from_pyfile('config.cfg')
eveapi.set_user_agent('GETIN HR app ({})'.format(app.config['CONTACT_EMAIL']))
xmlapi = eveapi.EVEAPIConnection()
prest = Prest(
    User_Agent='GETIN HR app ({})'.format(app.config['CONTACT_EMAIL']),
    client_id=app.config['EVE_OAUTH_CLIENT_ID'],
    client_secret=app.config['EVE_OAUTH_SECRET'],
    callback_url=app.config['EVE_OAUTH_CALLBACK']
)
reddit_oauth = RedditOAuth(
    app.config['REDDIT_OAUTH_CLIENT_ID'],
    app.config['REDDIT_OAUTH_SECRET'],
    app.config['REDDIT_OAUTH_CALLBACK']
)
db.app = app
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_message = ''
login_manager.login_view = 'check_access'


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        keys = request.form['keys']
        errors = []
        for key in keys.splitlines():
            try:
                keyID, vCode = key.strip().split(' - ')
                auth = xmlapi.auth(keyID=keyID, vCode=vCode)
                result = auth.account.APIKeyInfo()
                if not result.key.accessMask == app.config['API_KEY_MASK']:
                    errors.append('The key with ID "{}" has the wrong access mask. Has: {}, needs: {}'.format(
                        keyID, result.key.accessMask, app.config['API_KEY_MASK']
                    ))
            except Exception as e:
                errors.append('An error occurred with line "{}"'.format(key))
                print(str(e))
        if not errors:
            current_user.member.set_api_keys(keys.splitlines())
            flash('API key information saved', 'success')
        else:
            flash('; '.join(errors), 'error')
        return redirect(url_for('index'))
    reddit_link = reddit_oauth.get_authorize_url()
    return render_template('personal.html', reddit_link=reddit_link)


@app.route('/members', methods=['GET', 'POST'])
@login_required
def membership():
    if not current_user.member.status == 'Recruiter' and not current_user.admin:
        return redirect(url_for('index'))
    members = Member.query.filter_by(hidden=False).all()
    return render_template('membership.html', members=members)


@app.route('/members/add', methods=['GET', 'POST'])
@login_required
def add_member():
    if request.method == 'POST':
        name = request.form.get('name')
        reddit = request.form.get('reddit')
        status = request.form.get('status')
        apikey = request.form.get('apikey')
        apicode = request.form.get('apicode')
        alts = request.form.get('alts')
        notes = request.form.get('notes')
        member = Member(name, reddit, alts, status, notes)
        db.session.add(member)
        db.session.commit()
        db.session.add(APIKey(app.id, apikey, apicode))
        db.session.commit()
        flash('Character added', 'success')
    return render_template('add_member.html')


@app.route('/admin', methods=['GET', 'POSt'])
@login_required
def admin():
    if not current_user.admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        db.session.add(User(name))
        db.session.commit()
        flash(name + ' added as a recruiter', 'success')
        return redirect(url_for('admin'))
    admins = ', '.join([user.name for user in User.query.filter_by(admin=True).all()])
    recruiters = User.query.all()
    return render_template('admin.html', admins=admins, recruiters=recruiters)


@app.route('/admin/revoke/<name>')
def revoke_access(name):
    if not current_user.admin:
        return redirect(url_for('index'))
    User.query.filter_by(name=name).delete()
    db.session.commit()
    flash('User access revoked for ' + name, 'success')
    return redirect(url_for('admin'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    member = Member.query.get(id)
    if not member:
        flash('Unknown id', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        # TODO
        pass
    return render_template('edit.html')


@app.route('/join', methods=['GET', 'POST'])
def join():
    character_name = session.get('character_name') or current_user.name if not current_user.is_anonymous else None
    if not character_name:
        flash('Well, something went wrong. Try again?', 'error')
        return redirect(url_for('login'))
    member = current_user.member
    if request.method == 'POST':
        key = request.form['key']
        code = request.form['code']
        auth = xmlapi.auth(keyID=key, vCode=code)
        result = auth.account.APIKeyInfo()
        if not result.key.accessMask == app.config['API_KEY_MASK']:
            flash('Wrong key mask - you need {}'.format(app.config['API_KEY_MASK']), 'error')
            return redirect(url_for('join'))
        member = Member(character_name, 'New')
        db.session.add(member)
        db.session.commit()
        db.session.add(APIKey(member.id, key, code))
        db.session.commit()
        flash('Your application is in - someone will take a look soon', 'success')
        return redirect(url_for('join'))
    return render_template('join.html', character_name=character_name)


@app.route('/check_access')
def check_access():
    if current_user and not current_user.is_authenticated and not current_user.is_anonymous:
        return redirect(url_for('join'))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    url = prest.get_authorize_url()
    return render_template('login.html', url=url)


@app.route('/eve/callback')
def eve_oauth_callback():
    if 'error' in request.path:
        flash('There was an error in EVE\'s response', 'error')
        return url_for('login')
    auth = prest.authenticate(request.args['code'])
    character_info = auth.whoami()
    character_name = character_info['CharacterName']
    user = User.query.filter_by(name=character_name).first()
    if user:
        login_user(user)
        if user.member:
            flash('Logged in', 'success')
            return redirect(url_for('index'))
        return redirect(url_for('join'))
    character_affiliation = xmlapi.eve.CharacterAffiliation(ids=character_info['CharacterID'])
    corporation = character_affiliation.characters[0].corporationName
    user = User(character_name)
    db.session.add(user)
    db.session.add(Member(character_name, corporation, 'Member' if corporation == app.config['CORPORATION'] else 'New'))
    db.session.commit()
    login_user(user)
    if corporation == app.config['CORPORATION']:
        flash('Welcome to HR', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('join'))


@app.route('/reddit/callback')
@login_required
def reddit_oauth_callback():
    username = reddit_oauth.get_token(request.args['code'])
    current_user.member.reddit = username
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.errorhandler(404)
def error_404(e):
    return render_template('error_404.html')


@app.errorhandler(500)
def error_500(e):
    return render_template('error_500.html')
