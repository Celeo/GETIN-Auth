from flask import Flask, render_template, redirect, request, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import eveapi
from prest import Prest

from hr.shared import db
from hr.models import User, Application, APIKey


app = Flask(__name__)
app.config.from_pyfile('config.cfg')
xmlapi = eveapi.EVEAPIConnection()
prest = Prest(
    client_id=app.config['EVE_OAUTH_CLIENT_ID'],
    client_secret=app.config['EVE_OAUTH_SECRET'],
    callback_url=app.config['EVE_OAUTH_CALLBACK'],
    scope=''
)
db.app = app
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'eve_oauth_prompt'


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    applications = Application.query.filter_by(hidden=False).all()
    return render_template('index.html', applications=applications)


@app.route('/app/add', methods=['GET', 'POST'])
@login_required
def add_app():
    if request.method == 'POST':
        name = request.form.get('name')
        reddit = request.form.get('reddit')
        status = request.form.get('status')
        apikey = request.form.get('apikey')
        apicode = request.form.get('apicode')
        alts = request.form.get('alts')
        notes = request.form.get('notes')
        app = Application(name, reddit, alts, status, notes)
        db.session.add(app)
        db.session.commit()
        db.session.add(APIKey(app.id, apikey, apicode))
        db.session.commit()
        flash('Character added', 'success')
    return render_template('add_app.html')


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


@app.route('/eve_oauth/prompt')
def eve_oauth_prompt():
    url = prest.get_authorize_url()
    return render_template('eve_oauth_prompt.html', url=url)


@app.route('/eve_oauth/callback')
def eve_oauth_callback():
    if 'error' in request.path:
        flash('There was an error in EVE\'s response', 'error')
        return url_for('eve_oauth_prompt')
    auth = prest.authenticate(request.args['code'])
    character_name = auth.whoami()['CharacterName']
    user = User.query.filter_by(name=character_name).first()
    if not user:
        flash('You, {}, are not whitelisted to use this app'.format(character_name), 'error')
        return redirect(url_for('eve_oauth_prompt'))
    login_user(user)
    flash('Logged in', 'success')
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
