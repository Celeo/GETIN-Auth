import logging

from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import eveapi
from prest import Prest

from hr.shared import db
from hr.models import User, Member, APIKey
from hr.reddit_oauth import RedditOAuth


# Create and configure app
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
# EVE XML API connection
eveapi.set_user_agent('GETIN HR app ({})'.format(app.config['CONTACT_EMAIL']))
xmlapi = eveapi.EVEAPIConnection()
# EVE CREST API connection
prest = Prest(
    User_Agent='GETIN HR app ({})'.format(app.config['CONTACT_EMAIL']),
    client_id=app.config['EVE_OAUTH_CLIENT_ID'],
    client_secret=app.config['EVE_OAUTH_SECRET'],
    callback_url=app.config['EVE_OAUTH_CALLBACK']
)
# Reddit OAuth connection
reddit_oauth = RedditOAuth(
    app.config['REDDIT_OAUTH_CLIENT_ID'],
    app.config['REDDIT_OAUTH_SECRET'],
    app.config['REDDIT_OAUTH_CALLBACK']
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


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    """
    Member page.

    This is for logged in members to view their personal data. They
    can edit the API keys.

    Methods:
        GET
        POST

    Args:
        None

    Returns:
        rendered template 'personal.html'
    """
    if request.method == 'POST':
        app.logger.debug('POST on index by {}'.format(current_user.name))
        keys = request.form['keys']
        validate_keys(keys, current_user.member)
        return redirect(url_for('index'))
    reddit_link = reddit_oauth.get_authorize_url()
    return render_template('personal.html', reddit_link=reddit_link)


def validate_keys(keys, member):
    """
    This method validates a single- or multi-line string of API
    keys and codes separated by ' - ' against the EVE API to
    verify that they have the correct access mask.

    Args:
        keys (str) - text to parse and validate
        member (hr.models.Member) - Member to update if the keys are valid

    Returns:
        value (bool) if all keys were valid
    """
    errors = []
    for key in keys.splitlines():
        if not key:
            continue
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
    if not errors and member:
        member.set_api_keys(keys.splitlines())
        db.session.commit()
        flash('API key information saved', 'success')
    else:
        flash('; '.join(errors), 'error')
    return not errors


@app.route('/members')
@login_required
def membership():
    """
    Recruiter page.

    This page shows recruiters the total list of members of the corporation
    and the applications to join the corporation.

    Args:
        None

    Returns:
        rendered template 'membership.html'
    """
    if not current_user.member.status == 'Recruiter' and not current_user.admin:
        return redirect(url_for('index'))
    show_hidden = request.args.get('show_hidden', 0, type=bool)
    show_applications = request.args.get('show_applications', 0, type=bool)
    members = Member.query.filter_by(hidden=show_hidden).all()
    if show_applications:
        members = [member for member in members if member.status in
            ['Guest', 'New', 'Ready to be interviewed', 'Ready to be accepted']]
    members = sorted(members, key=lambda x: x.character_name)
    return render_template('membership.html',
        members=members, show_hidden=show_hidden, show_applications=show_applications)


@app.route('/members/add', methods=['GET', 'POST'])
@login_required
def add_member():
    """
    This page allows recruiters to manually add an applicant.

    Methods:
        GET
        POST

    Args:
        None

    Returns:
        rendered template 'add_applicant.html'
    """
    if not current_user.member.status == 'Recruiter' and not current_user.admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        app.logger.debug('POST on add_member by {}'.format(current_user.name))
        name = request.form.get('name')
        reddit = request.form.get('reddit')
        status = request.form.get('status')
        apikey = request.form.get('apikey')
        apicode = request.form.get('apicode')
        if not validate_keys('{} - {}'.format(apikey, apicode), None):
            return redirect(url_for('add_member'))
        alts = request.form.get('alts')
        notes = request.form.get('notes')
        member = Member(name, get_corp_for_name(name), status, reddit, alts, notes)
        db.session.add(member)
        db.session.commit()
        db.session.add(APIKey(member.id, apikey, apicode))
        db.session.commit()
        flash('Character added', 'success')
    return render_template('add_applicant.html')


@app.route('/admin', methods=['GET', 'POSt'])
@login_required
def admin():
    """
    This is the admin control page, where admins can add and remove
    recruiters and pull all corp members from the EVE API to update
    the database.

    Methods:
        GET
        POST

    Args:
        None

    Returns:
        rendered template 'admin.html'
    """
    if not current_user.admin:
        app.logger.debug('Admin access denied to {}'.format(current_user.name))
        return redirect(url_for('index'))
    if request.method == 'POST':
        app.logger.debug('POST on admin by {}'.format(current_user.name))
        name = request.form['name']
        member = Member.query.filter_by(character_name=name).first()
        if not member:
            flash('Unknown member', 'error')
            return redirect(url_for('admin'))
        member.status = 'Recruiter'
        db.session.commit()
        flash(member.character_name + ' promoted to recruiter', 'success')
        return redirect(url_for('admin'))
    admins = ', '.join([user.name for user in User.query.filter_by(admin=True).all()])
    recruiters = Member.query.filter_by(status='Recruiter').all()
    recruiters.extend([user.member for user in User.query.filter_by(admin=True).all()])
    recruiters = sorted(set(recruiters), key=lambda x: x.character_name)
    return render_template('admin.html', admins=admins, recruiters=recruiters)


@app.route('/admin/revoke/<name>')
@login_required
def revoke_access(name):
    """
    This transient endpoint allows an admin to revoke the recruiter
    status of a member.

    Args:
        name (str) - name of the recruiter to revoke

    Returns:
        redirect to the admin endpoint
    """
    if not current_user.admin:
        return redirect(url_for('index'))
    member = Member.query.filter_by(character_name=name).first()
    if not member:
        flash('Unknown member name', 'error')
        return redirect(url_for('admin'))
    member.status = 'Accepted'
    db.session.commit()
    flash('User access revoked for ' + name, 'success')
    return redirect(url_for('admin'))


@app.route('/details/<int:id>', methods=['GET', 'POST'])
@login_required
def details(id):
    """
    This page allows recruiters to view and edit a member's details.

    Methods:
        GET
        POST

    Args:
        id (int) - id of the member to examine

    Returns:
        rendered template 'details.html'
    """
    if not current_user.member.status == 'Recruiter' and not current_user.admin:
        app.logger.debug('Details access denied to {}'.format(current_user.name))
        return redirect(url_for('index'))
    member = Member.query.get(id)
    if not member:
        flash('Unknown id', 'error')
        app.logger.error('Unknown id on details for id {} by {}'.format(id, current_user.name))
        return redirect(url_for('membership'))
    if request.method == 'POST':
        app.logger.debug('POST on details by {}'.format(current_user.name))
        if request.form['section'] == 'keys':
            validate_keys(request.form['keys'], member)
        elif request.form['section'] == 'status':
            member.status = request.form['status']
            db.session.commit()
            flash('Status changed', 'success')
        elif request.form['section'] == 'main':
            member.main = request.form['main']
            db.session.commit()
            flash('Main character changed', 'success')
        else:
            flash('Unknown form submission', 'error')
        return redirect(url_for('details', id=id))
    return render_template('details.html', member=member)


@app.route('/visibility/<int:id>/<action>')
@login_required
def visibility(id, action):
    """
    This transient endpoint allows a recruiter to set the visiblity
    of a member on the membership page (to be used to hide people who
    have left the corp).

    Args:
        id (int) - id of the member to modify
        action (str) - whether to hide or show the member

    Returns:
        redirect to the member's details endpoint
    """
    if not current_user.member.status == 'Recruiter' and not current_user.admin:
        app.logger.debug('Visibility access denied to {}'.format(current_user.name))
        return redirect(url_for('index'))
    member = Member.query.get(id)
    if not member:
        flash('Unknown id', 'error')
        app.logger.error('Unknown id on details for id {} by {}'.format(id, current_user.name))
        return redirect(url_for('membership'))
    member.hidden = action == 'hide'
    db.session.commit()
    flash('"{}" {}'.format(member.character_name, 'hidden' if member.hidden else 'made visible'), 'success')
    return redirect(url_for('details', id=id))


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    """
    This transient endpoint allows an admin to permanently delete a
    member from the database.

    Args:
        id (int) - id of the member to delete

    Returns:
        redirect to the membership endpoint
    """
    if not current_user.admin:
        app.logger.debug('Delete access denied to {}'.format(current_user.name))
        return redirect(url_for('details', id=id))
    Member.query.filter_by(id=id).delete()
    db.session.commit()
    flash('Member deleted', 'success')
    return redirect(url_for('membership'))


@app.route('/join', methods=['GET', 'POST'])
def join():
    """
    This page allows a user to submit an application to join the corporation
    by supplying an API key and optional reddit account and main character.

    Methods:
        GET
        POST

    Args:
        None

    Returns:
        rendered tempalte 'join.html'
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    character_name = session.get('character_name') or current_user.name if not current_user.is_anonymous else None
    if not character_name:
        flash('Well, something went wrong. Try again?', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        app.logger.debug('POST on join by {}'.format(current_user.name))
        try:
            key = request.form['key']
            code = request.form['code']
            auth = xmlapi.auth(keyID=key, vCode=code)
            main = request.form.get('main')
            result = auth.account.APIKeyInfo()
            if not result.key.accessMask == app.config['API_KEY_MASK']:
                flash('Wrong key mask - you need {}'.format(app.config['API_KEY_MASK']), 'error')
                return redirect(url_for('join'))
            current_user.member.status = 'New'
            current_user.member.main = main
            db.session.add(APIKey(current_user.member.id, key, code))
            db.session.commit()
            flash('Your application is in - someone will take a look soon', 'success')
        except Exception:
            flash('An error occurred when parsing your API key. Are you sure you entered it right?', 'error')
        return redirect(url_for('join'))
    reddit_link = reddit_oauth.get_authorize_url()
    return render_template('join.html', character_name=character_name, reddit_link=reddit_link)


@app.route('/sync')
@login_required
def sync():
    """
    This transient endpoint allows an admin to import a list of corporation
    members from the EVE API, updating any missing models from the database
    and marking characters that have left (or been kicked from) the corporation
    as being gone.

    Args:
        None

    Returns:
        redirect to the admin endpoint
    """
    if not current_user.admin:
        app.logger.debug('Admin access denied to {}'.format(current_user.name))
        return redirect(url_for('index'))
    app.logger.info('-- Starting member sync')
    auth = xmlapi.auth(keyID=app.config['CORP_MEMBER_API_KEY'], vCode=app.config['CORP_MEMBER_API_CODE'])
    members = auth.corp.MemberTracking().members
    api_members = []
    for member in members:
        db_model = Member.query.filter_by(character_name=member.name).first()
        if not db_model:
            app.logger.info('-- Added {} to the corporation'.format(member.name))
            db.session.add(Member(member.name, app.config['CORPORATION'], 'Accepted'))
        elif db_model.status not in ['Accepted', 'Recruiter']:
            db_model.status = 'Accepted'
            app.logger.info('-- {} has been accepted into the corporation'.format(member.name))
        api_members.append(member.name)
    for member in Member.query.filter_by(status='Accepted').all():
        if member.character_name not in api_members:
            app.logger.warning('-- ' + member.character_name + ' is not in the corporation')
            member.status = 'Left'
            member.hidden = True
    try:
        db.session.commit()
        app.logger.info('-- Database saved after member sync')
    except Exception as e:
        app.logger.error('-- An error occurred when syncing membrs: ' + str(e))
    flash('Members imported', 'success')
    return redirect(url_for('admin'))


@app.route('/reports')
@login_required
def reports():
    """
    This page shows reports to the recruiters for the purpose of validation
    and security.

    Args:
        None

    Returns:
        Rendered template 'reports.html'
    """
    if not current_user.member.status == 'Recruiter' and not current_user.admin:
        app.logger.debug('Visibility access denied to {}'.format(current_user.name))
        return redirect(url_for('index'))
    members = Member.query.all()
    member_names = map(lambda x: x.character_name, members)
    defunct_alts = []
    invalid_mains = []
    for member in members:
        if member.character_name != member.main:
            if member.main not in member_names:
                invalid_mains.append(member)
            elif [m for m in members if m.character_name == member.main][0].status == 'Left':
                defunct_alts.append(member)
    return render_template('reports.html', defunct_alts=defunct_alts, invalid_mains=invalid_mains)


@app.route('/check_access')
def check_access():
    """
    This transient endpoint checks where a user should be redirect to.

    Args:
        None

    Returns:
        redirect to the index , join, or login endpoints
    """
    if current_user and not current_user.is_anonymous:
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        return redirect(url_for('join'))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    """
    This page shows a user the EVE SSO link so they can log in.

    Args:
        None

    Returns;
        rendered template 'login.html'
    """
    return render_template('login.html', url=prest.get_authorize_url())


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
        auth = prest.authenticate(request.args['code'])
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
    db.session.add(Member(character_name, corporation, 'Accepted' if corporation == app.config['CORPORATION'] else 'Guest'))
    db.session.commit()
    login_user(user)
    app.logger.info('{} created an account via EVE SSO'.format(current_user.name))
    if corporation == app.config['CORPORATION']:
        flash('Welcome to HR', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('join'))


@app.route('/reddit/callback')
def reddit_oauth_callback():
    """
    This transient endpoint completes the reddit OAuth verification process
    and sets the current user's reddit account in the database.

    Args:
        None

    Returns:
        redirect to the index endpoint
    """
    if current_user.is_anonymous:
        return redirect(url_for('login'))
    app.logger.debug('Reddit callback by {}'.format(current_user.name))
    username = reddit_oauth.get_token(request.args['code'])
    current_user.member.reddit = username
    db.session.commit()
    return redirect(url_for('index'))


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
    return get_corp_for_id(xmlapi.eve.CharacterID(names=name).characters[0].characterID)


def get_corp_for_id(id):
    """
    This helper method takes a character's id and returns their corporation name.

    Args:
        name (str) - full character name

    Returns:
        value (str) of their corporation's name
    """
    return xmlapi.eve.CharacterAffiliation(ids=id).characters[0].corporationName
