from flask import Flask, render_template, redirect, request, session, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required
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
    callback_url=app.config['EVE_OAUTH_CALLBACK']
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
    if request.method == 'POST':
        # TODO
        pass
    applications = Application.query.filter_by(hidden=False).all()
    return render_template('index.html', applications=applications)


@app.route('/eve_oauth/prompt')
def eve_oauth_prompt():
    url = prest.get_authorize_url()
    return render_template('eve_oauth_prompt.html', url=url)


@app.route('/eve_oauth/callback')
def eve_oauth_callback():
    if 'error' in request.path:
        flash('There was an error in EVE\'s response.', 'error')
        return url_for('eve_oauth_prompt')
    user = User.query.filter_by(name=session['character_name']).first()
    if not user:
        return render_template('no_access.html')
    login_user(user)
    flash('Logged in', 'success')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
