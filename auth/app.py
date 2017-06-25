import logging
from datetime import timedelta

from flask import Flask, render_template, redirect, request, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from preston.crest import Preston as CREST
from preston.xmlapi import Preston as XMLAPI

from auth.shared import db, eveapi
from auth.models import User
from auth.hr.app import app as hr_blueprint, update_member
from auth.wiki.app import app as wiki_blueprint


# Create and configure app
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=14)
app.config.from_pyfile('config.cfg')
# EVE XML API connection
user_agent = 'GETIN HR app ({})'.format(app.config['CONTACT_EMAIL'])
eveapi['user_agent'] = user_agent
eveapi['xml'] = XMLAPI(user_agent=user_agent)
# EVE CREST API connection
eveapi['crest'] = CREST(
    user_agent=user_agent,
    client_id=app.config['EVE_OAUTH_CLIENT_ID'],
    client_secret=app.config['EVE_OAUTH_SECRET'],
    callback_url=app.config['EVE_OAUTH_CALLBACK']
)
# Database connection
db.app = app
db.init_app(app)
# User management
login_manager = LoginManager(app)
login_manager.login_message = ''
login_manager.login_view = 'login'
# Application logging
app.logger.setLevel(app.config['LOGGING_LEVEL'])
handler = logging.FileHandler('log.txt')
handler.setFormatter(logging.Formatter(style='{', fmt='{asctime} [{levelname}] {message}', datefmt='%Y-%m-%d %H:%M:%S'))
handler.setLevel(app.config['LOGGING_LEVEL'])
app.logger.addHandler(handler)
# Blueprints
app.register_blueprint(hr_blueprint, url_prefix='/hr')
app.register_blueprint(wiki_blueprint, url_prefix='/wiki')


app.logger.info('Initialization complete')


@login_manager.user_loader
def load_user(user_id):
    """Takes a string int and returns a auth.models.User object for Flask-Login.

    Args:
        user_id (str): user model id

    Returns:
        auth.models.User: user with that id
    """
    return User.query.filter_by(id=int(user_id)).first()


@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/login')
def login():
    """Shows a user the EVE SSO link so they can log in.

    Args:
        None

    Returns;
        str: rendered template 'login.html'
    """
    return render_template('login.html', url=eveapi['crest'].get_authorize_url())


@app.route('/eve/callback')
def eve_oauth_callback():
    """Completes the EVE SSO login. Here, hr.models.User models
    and hr.models.Member models are created for the user if they don't
    exist and the user is redirected the the page appropriate for their
    access level.

    Args:
        None

    Returns:
        str: redirect to the login endpoint if something failed, join endpoint if
        the user is a new user, or the index endpoint if they're already a member.
    """
    if 'error' in request.path:
        app.logger.error('Error in EVE SSO callback: ' + request.url)
        flash('There was an error in EVE\'s response', 'error')
        return url_for('login')
    try:
        auth = eveapi['crest'].authenticate(request.args['code'])
    except Exception as e:
        app.logger.error('CREST signing error: ' + str(e))
        flash('There was an authentication error signing you in.', 'error')
        return redirect(url_for('login'))
    character_info = auth.whoami()
    character_name = character_info['CharacterName']
    user = User.query.filter_by(name=character_name).first()
    if user:
        login_user(user)
        update_member(character_name)
        app.logger.debug('{} logged in with EVE SSO'.format(current_user.name))
        flash('Logged in', 'success')
        return redirect(url_for('landing'))
    corporation = get_corp_for_name(character_name)
    user = User(character_name, corporation)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    app.logger.info('{} created an account'.format(current_user.name))
    return redirect(url_for('landing'))


@app.route('/logout')
def logout():
    """Logs the user out of the site.

    Args:
        None

    Returns:
        str: redirect to the login endpoint
    """
    app.logger.debug('{} logged out'.format(current_user.name if not current_user.is_anonymous else 'unknown user'))
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(404)
def error_404(e):
    """Catches 404 errors in the app and shows the user an error page.

    Args:
        e (Exception): the exception from the server

    Returns:
        str: rendered template 'error_404.html'
    """
    app.logger.error('404 error at "{}" by {}: {}'.format(
        request.url, current_user.name if not current_user.is_anonymous else 'unknown user', str(e))
    )
    return render_template('error_404.html')


@app.errorhandler(500)
def error_500(e):
    """Catches 500 errors in the app and shows the user an error page.

    Args:
        e (Exception): the exception from the server

    Returns:
        str: rendered template 'error_404.html'
    """
    app.logger.error('500 error at "{}" by {}: {}'.format(
        request.url, current_user.name if not current_user.is_anonymous else 'unknown user', str(e))
    )
    return render_template('error_500.html')


def get_corp_for_name(name):
    """Takes a character's name and returns their EVE character ID.

    Args:
        name (str): full character name

    Returns:
        int: value of their EVE character ID
    """
    return get_corp_for_id(eveapi['xml'].eve.CharacterId(names=name)['rowset']['row']['@characterID'])


def get_corp_for_id(id):
    """Takes a character's id and returns their corporation name.

    Args:
        name (str): full character name

    Returns:
        str: value of their corporation's name
    """
    return eveapi['xml'].eve.CharacterAffiliation(ids=id)['rowset']['row']['@corporationName']
