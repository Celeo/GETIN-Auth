import logging

from flask import Flask, render_template, redirect, request, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from preston.crest import Preston as CREST
from preston.xmlapi import Preston as XMLAPI

from .shared import db
from .models import User, Member


# Create and configure app
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
# EVE XML API connection
user_agent = 'GETIN HR app ({})'.format(app.config['CONTACT_EMAIL'])
xmlapi = XMLAPI(user_agent=user_agent)
# EVE CREST API connection
crest = CREST(
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
login_manager.login_view = 'check_access'
# Application logging
app.logger.setLevel(app.config['LOGGING_LEVEL'])
handler = logging.FileHandler('log.txt')
handler.setFormatter(logging.Formatter(style='{', fmt='{asctime} [{levelname}] {message}', datefmt='%Y-%m-%d %H:%M:%S'))
handler.setLevel(app.config['LOGGING_LEVEL'])
app.logger.addHandler(handler)
app.logger.info('Initialization complete')
# Storage for API calls
new_apps = []


@login_manager.user_loader
def load_user(user_id):
    """
    Takes a string int and returns a hr.models.User object for Flask-Login.

    Args:
        user_id (str) - user model id

    Returns:
        user (hr.models.User) with that id
    """
    return User.query.filter_by(id=int(user_id)).first()


@app.route('/login')
def login():
    """
    This page shows a user the EVE SSO link so they can log in.

    Args:
        None

    Returns;
        rendered template 'login.html'
    """
    return render_template('login.html', url=crest.get_authorize_url())


@app.route('/eve/callback')
def eve_oauth_callback():
    """
    This transient endpoint completes the EVE SSO login. Here, hr.models.User models
    and hr.models.Member models are created for the user if they don't
    exist and the user is redirected the the page appropriate for their
    access level.

    Args:
        None

    Returns:
        redirect to the login endpoint if something failed, join endpoint if
        the user is a new user, or the index endpoint if they're already a member.
    """
    if 'error' in request.path:
        app.logger.error('Error in EVE SSO callback: ' + request.url)
        flash('There was an error in EVE\'s response', 'error')
        return url_for('login')
    try:
        auth = crest.authenticate(request.args['code'])
    except Exception as e:
        app.logger.error('CREST signing error: ' + str(e))
        flash('There was an authentication error signing you in.', 'error')
        return redirect(url_for('login'))
    character_info = auth.whoami()
    character_name = character_info['CharacterName']
    user = User.query.filter_by(name=character_name).first()
    if user:
        if not user.member:
            app.logger.info('Created a Member object for user {}'.format(user.name))
            corporation = get_corp_for_name(user.name)
            db.session.add(Member(user.name, corporation, 'Accepted' if corporation == app.config['CORPORATION'] else 'Guest'))
            db.session.commit()
        login_user(user)
        app.logger.debug('{} logged in with EVE SSO'.format(current_user.name))
        if user.member:
            flash('Logged in', 'success')
            return redirect(url_for('index'))
        return redirect(url_for('join'))
    user = User(character_name)
    db.session.add(user)
    corporation = get_corp_for_name(character_name)
    member = Member.query.filter_by(character_name=character_name).first()
    if not member:
        db.session.add(Member(character_name, corporation, 'Accepted' if corporation == app.config['CORPORATION'] else 'Guest'))
        app.logger.info('Added a new member object for {} from their first login'.format(character_name))
    else:
        app.logger.debug('{} logged in for the first time, but a member object already existed for them'.format(character_name))
    db.session.commit()
    login_user(user)
    app.logger.info('{} created an account via EVE SSO'.format(current_user.name))
    if corporation == app.config['CORPORATION']:
        flash('Welcome to HR', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('join'))


@app.route('/logout')
def logout():
    """
    This transient endpoint logs the user out of the site.

    Args:
        None

    Returns:
        redirect to the login endpoint
    """
    app.logger.debug('{} logged out'.format(current_user.name if not current_user.is_anonymous else 'unknown user'))
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(404)
def error_404(e):
    """
    This page catches 404 errors in the app and shows the user an error page.

    Args:
        e (Exception) - the exception from the server

    Returns:
        rendered template 'error_404.html'
    """
    app.logger.error('404 error at "{}" by {}: {}'.format(
        request.url, current_user.name if not current_user.is_anonymous else 'unknown user', str(e))
    )
    return render_template('error_404.html')


@app.errorhandler(500)
def error_500(e):
    """
    This page catches 500 errors in the app and shows the user an error page.

    Args:
        e (Exception) - the exception from the server

    Returns:
        rendered template 'error_404.html'
    """
    app.logger.error('500 error at "{}" by {}: {}'.format(
        request.url, current_user.name if not current_user.is_anonymous else 'unknown user', str(e))
    )
    return render_template('error_500.html')


def get_corp_for_name(name):
    """
    This helper method takes a character's name and returns their EVE character ID.
    Args:
        name (str) - full character name
    Returns:
        value (int) of their EVE character ID
    """
    return get_corp_for_id(xmlapi.eve.CharacterId(names=name)['rowset']['row']['@characterID'])


def get_corp_for_id(id):
    """
    This helper method takes a character's id and returns their corporation name.
    Args:
        name (str) - full character name
    Returns:
        value (str) of their corporation's name
    """
    return xmlapi.eve.CharacterAffiliation(ids=id)['rowset']['row']['@corporationName']
