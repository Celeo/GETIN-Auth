from functools import wraps

from flask import Blueprint, current_app, render_template, redirect, request, url_for, flash, session, abort, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_
from preston.xmlapi import Preston as XMLAPI

from auth.shared import db, eveapi
from auth.models import User
from .models import Member
from .reddit_oauth import RedditOAuth


# Create and configure app
app = Blueprint('hr', __name__, template_folder='templates/hr', static_folder='static')
# Reddit OAuth connection
reddit_oauth = None
# Storage for API calls
new_apps = []


@app.record
def _record(setup_state):
    app.config = setup_state.app.config
    global reddit_oauth
    reddit_oauth = RedditOAuth(
        app.config['REDDIT_OAUTH_CLIENT_ID'],
        app.config['REDDIT_OAUTH_SECRET'],
        app.config['REDDIT_OAUTH_CALLBACK']
    )


@app.context_processor
def _prerender():
    if current_user.is_authenticated:
        return {
            'member': Member.query.filter_by(character_name=current_user.name).first()
        }
    return {}


@app.before_request
def _preprocess():
    member = get_member_for(current_user)
    if not member and not current_user.is_anonymous:
        db.session.add(Member(current_user.name, get_corp_for_name(current_user.name)))
        db.session.commit()


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
        current_app.logger.debug('POST on index by {}'.format(current_user.name))
        key_id = request.form['key_id']
        v_code = request.form['v_code']
        validate_key(key_id, v_code, get_member_for(current_user))
        return redirect(url_for('.index'))
    reddit_link = reddit_oauth.get_authorize_url()
    return render_template('hr/personal.html', reddit_link=reddit_link)


def validate_key(key_id, v_code, member):
    """
    This method validates a single- or multi-line string of API
    keys and codes separated by ' - ' against the EVE API to
    verify that they have the correct access mask.

    Args:
        key_id (str) - EVE API key keyID
        v_code (str) - EVE API key vCode
        member (hr.models.Member) - Member to update if the keys are valid

    Returns:
        value (bool) if all keys were valid
    """
    errors = []
    try:
        auth = XMLAPI(key=key_id, code=v_code, user_agent=eveapi['user_agent'])
        result = auth.account.APIKeyInfo()
        if not int(result['key']['@accessMask']) == app.config['API_KEY_MASK']:
            errors.append('The key with ID "{}" has the wrong access mask. Has: {}, needs: {}'.format(
                key_id, result['key']['@accessMask'], app.config['API_KEY_MASK']
            ))
    except Exception as e:
        errors.append('An error occurred with keyID "{}"'.format(key_id))
        errors.append('An error occurred with keyID "{}": {}'.format(key_id, str(e)))
    if not errors and member:
        member.key_id = key_id
        member.v_code = v_code
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
    if not current_user.recruiter and not current_user.mentor and not current_user.admin:
        return redirect(url_for('.index'))
    show_hidden = request.args.get('show_hidden', 0, type=bool)
    show_applications = request.args.get('show_applications', 0, type=bool)
    members = Member.query.filter_by(hidden=show_hidden).all()
    if show_applications:
        members = [member for member in members if member.status in
            ['New', 'Ready to be interviewed', 'Ready to be accepted']]
    members = sorted(members, key=lambda x: x.character_name.lower())
    return render_template('hr/membership.html',
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
    if not current_user.recruiter and not current_user.admin:
        return redirect(url_for('.index'))
    if request.method == 'POST':
        name = request.form.get('name')
        reddit = request.form.get('reddit')
        status = request.form.get('status')
        apikey = request.form.get('apikey')
        apicode = request.form.get('apicode')
        main = request.form.get('main')
        if main == '*':
            main = name
        notes = request.form.get('notes')
        current_app.logger.debug('POST on add_member by {}: name = {}, reddit = {}, status = {}, main = {}'.format(
            current_user.name, name, reddit, status, main
        ))
        if not validate_key('{} - {}'.format(apikey, apicode), None):
            current_app.logger.info('POST on add_member didn\'t have a valid key')
            flash('Invalid key for user', 'danger')
            return redirect(url_for('.add_member'))
        member = Member(name, get_corp_for_name(name), status, reddit, main, notes, apikey, apicode)
        current_app.logger.info('New member added through add_member: ' + str(name))
        db.session.add(member)
        db.session.commit()
        db.session.commit()
        flash('Character added', 'success')
    return render_template('hr/add_member.html', all_members=get_all_member_names())


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
        current_app.logger.debug('Admin access denied to {}'.format(current_user.name))
        return redirect(url_for('.index'))
    if request.method == 'POST':
        current_app.logger.debug('POST on admin by {}'.format(current_user.name))
        name = request.form['name']
        member = Member.query.filter_by(character_name=name).first()
        if not member:
            flash('Unknown member', 'error')
            return redirect(url_for('.admin'))
        member.status = 'Accepted'
        if request.form['role'] == 'Recruiter':
            member.user.recruiter = True
        if request.form['role'] == 'Mentor':
            member.user.mentor = True
        db.session.commit()
        flash(member.character_name + ' promoted to ' + request.form['role'], 'success')
        return redirect(url_for('.admin'))
    admins = ', '.join([user.name for user in User.query.filter_by(admin=True).all()])

    recruiters = [get_member_for(user) for user in User.query.filter(or_(User.recruiter, User.admin)).all()]
    mentors = [get_member_for(user) for user in User.query.filter(or_(User.mentor, User.admin)).all()]

    recruiters = sorted(set(recruiters), key=lambda x: x.character_name)
    mentors = sorted(set(mentors), key=lambda x: x.character_name)
    return render_template('hr/admin.html',
        admins=admins, recruiters=recruiters, mentors=mentors, all_members=get_all_member_names())


@app.route('/admin/set_status', methods=['POST'])
@login_required
def admin_set_status():
    """
    This transient endpoint allows an admin to set the
    status of a member.

    Methods:
        POST

    Args:
        None

    Returns:
        redirect to the admin endpoint
    """
    if not current_user.admin:
        return redirect(url_for('.index'))
    if not request.method == 'POST':
        return redirect(url_for('.admin'))
    name = request.form.get('name', None)
    status = request.form.get('status', 'New')
    if not name or not status:
        flash('Missing name or status', 'error')
        return redirect(url_for('.admin'))
    member = Member.query.filter_by(character_name=name).first()
    if not member:
        flash('Unknown member name', 'error')
        return redirect(url_for('.admin'))
    member.status = status
    db.session.commit()
    flash('User status changed for ' + name + ' to ' + status, 'success')
    return redirect(url_for('.admin'))


@app.route('/admin/revoke/<name>/<role>')
@login_required
def revoke_access(name, role):
    """
    This transient endpoint allows an admin to revoke the recruiter
    status of a member.

    Args:
        name (str) - name of the recruiter to revoke

    Returns:
        redirect to the admin endpoint
    """
    if not current_user.admin:
        return redirect(url_for('.index'))
    member = Member.query.filter_by(character_name=name).first()
    if not member:
        flash('Unknown member name', 'error')
        return redirect(url_for('.admin'))
    member.status = 'Accepted'
    if role == 'Recruiter':
        member.user.recruiter = False
    elif role == 'Mentor':
        member.user.mentor = False
    db.session.commit()
    flash('User access revoked for ' + name, 'success')
    return redirect(url_for('.admin'))


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
    if not current_user.recruiter and not current_user.mentor and not current_user.admin:
        current_app.logger.debug('Details access denied to {}'.format(current_user.name))
        return redirect(url_for('.index'))
    member = Member.query.get(id)
    if not member:
        flash('Unknown id', 'error')
        current_app.logger.error('Unknown id on details for id {} by {}'.format(id, current_user.name))
        return redirect(url_for('.membership'))
    if request.method == 'POST':
        if request.form['section'] == 'keys':
            current_app.logger.info('POST on details - keys by {} for {}'.format(
                current_user.name, member.character_name
            ))
            validate_key(request.form['keys'], member)
        elif request.form['section'] == 'status':
            current_app.logger.info('POST on details - status by {} for {}: {}'.format(
                current_user.name, member.character_name, request.form['status']
            ))
            member.status = request.form['status']
            if member.status == 'Denied':
                member.hidden = True
            db.session.commit()
            flash('Status changed', 'success')
        elif request.form['section'] == 'main':
            current_app.logger.info('POST on details - main by {} for {}: {}'.format(
                current_user.name, member.character_name, request.form['main']
            ))
            main = request.form['main']
            member.main = main if not main == '*' else member.character_name
            db.session.commit()
            flash('Main character changed', 'success')
        elif request.form['section'] == 'notes':
            current_app.logger.info('POST on details - notes by {} for {}: {}'.format(
                current_user.name, member.character_name, request.form['notes']
            ))
            member.notes = request.form['notes']
            db.session.commit()
            flash('Notes changed', 'success')
        elif request.form['section'] == 'training':
            current_app.logger.info('POST on details - training by {} for {}'.format(
                current_user.name, member.character_name
            ))
            member.know_good_fits = 'know_good_fits' in request.form
            member.know_scan = 'know_scan' in request.form
            member.know_mass_and_time = 'know_mass_and_time' in request.form
            member.know_organize_gank = 'know_organize_gank' in request.form
            member.know_when_to_pve = 'know_when_to_pve' in request.form
            member.know_comms = 'know_comms' in request.form
            member.know_appropriate_ships = 'know_appropriate_ships' in request.form
            member.know_intel = 'know_intel' in request.form
            member.know_pvp = 'know_pvp' in request.form
            member.know_doctrine = 'know_doctrine' in request.form
            for alt in member.get_alts():
                alt.know_good_fits = member.know_good_fits
                alt.know_scan = member.know_scan
                alt.know_mass_and_time = member.know_mass_and_time
                alt.know_organize_gank = member.know_organize_gank
                alt.know_when_to_pve = member.know_when_to_pve
                alt.know_comms = member.know_comms
                alt.know_appropriate_ships = member.know_appropriate_ships
                alt.know_intel = member.know_intel
                alt.know_pvp = member.know_pvp
                alt.know_doctrine = member.know_doctrine
            db.session.commit()
        else:
            flash('Unknown form submission', 'error')
        return redirect(url_for('.details', id=id))
    return render_template('hr/details.html', member=member, all_members=get_all_member_names())


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
    if not current_user.recruiter and not current_user.admin:
        current_app.logger.debug('Visibility access denied to {}'.format(current_user.name))
        return redirect(url_for('.index'))
    member = Member.query.get(id)
    if not member:
        flash('Unknown id', 'error')
        current_app.logger.error('Unknown id on details for id {} by {}'.format(id, current_user.name))
        return redirect(url_for('.membership'))
    member.hidden = action == 'hide'
    db.session.commit()
    flash('"{}" {}'.format(member.character_name, 'hidden' if member.hidden else 'made visible'), 'success')
    return redirect(url_for('.details', id=id))


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
        current_app.logger.debug('Delete access denied to {}'.format(current_user.name))
        return redirect(url_for('.details', id=id))
    Member.query.filter_by(id=id).delete()
    db.session.commit()
    flash('Member deleted', 'success')
    return redirect(url_for('.membership'))


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
        return redirect(url_for('.index'))
    character_name = session.get('character_name') or current_user.name if not current_user.is_anonymous else None
    if not character_name:
        flash('Well, something went wrong. Try again?', 'error')
        return redirect(url_for('.login'))
    if request.method == 'POST':
        current_app.logger.debug('POST on join by {}'.format(current_user.name))
        try:
            key = request.form['key']
            code = request.form['code']
            auth = XMLAPI(key=key, code=code, user_agent=eveapi['user_agent'])
            main = request.form.get('main')
            reddit = None
            if main == '*':
                main = get_member_for(current_user).character_name
            else:
                try:
                    reddit = Member.query.filter_by(character_name=main).first().reddit
                except Exception:
                    current_app.logger.warning('{} tried to set {} as their main, but that Member object wasn\'t found'.format(
                        current_user.name, main
                    ))
            result = auth.account.APIKeyInfo()
            if not int(result['key']['@accessMask']) == app.config['API_KEY_MASK']:
                flash('Wrong key mask - you need {}'.format(app.config['API_KEY_MASK']), 'error')
                return redirect(url_for('.join'))
            get_member_for(current_user).status = 'New'
            get_member_for(current_user).main = main
            get_member_for(current_user).key_id = key
            get_member_for(current_user).v_code = code
            get_member_for(current_user).reddit = reddit
            db.session.commit()
            new_apps.append(current_user.name)
            flash('Your application is in - someone will take a look soon', 'success')
        except Exception:
            flash('An error occurred when parsing your API key. Are you sure you entered it right?', 'error')
        return redirect(url_for('.join'))
    reddit_link = reddit_oauth.get_authorize_url()
    return render_template('hr/join.html',
        character_name=character_name, reddit_link=reddit_link, all_members=get_all_member_names())


@app.route('/sync')
@login_required
def sync():
    """
    This transient endpoint calls the sync_members method.

    Args:
        None

    Returns:
        redirect to the admin endpoint
    """
    if not current_user.admin:
        current_app.logger.debug('Admin access denied to {}'.format(current_user.name))
        return redirect(url_for('.index'))
    sync_members()
    return redirect(url_for('.admin'))


def sync_members():
    """
    This method allows an admin to import a list of corporation
    members from the EVE API, updating any missing models from the database
    and marking characters that have left (or been kicked from) the corporation
    as being gone.

    Args:
        None

    Returns:
        value (dict) of membership changes
    """
    current_app.logger.info('-- Starting member sync')
    auth = XMLAPI(
        key=app.config['CORP_MEMBER_API_KEY'],
        code=app.config['CORP_MEMBER_API_CODE'],
        user_agent=eveapi['user_agent']
    )
    api_members = []
    existing_members, new_members, left_members = [], [], []
    for member in auth.corp.MemberTracking()['rowset']['row']:
        name = member['@name']
        db_model = Member.query.filter_by(character_name=name).first()
        if not db_model:
            current_app.logger.info('-- Added {} to the corporation'.format(name))
            existing_members.append(name)
            db_model = Member(name, app.config['CORPORATION'], 'Accepted')
            db.session.add(db_model)
        db_model.corporation = app.config['CORPORATION']
        if db_model.status not in ['Accepted', 'Recruiter']:
            db_model.status = 'Accepted'
            new_members.append(name)
            current_app.logger.info('-- {} has been accepted into the corporation'.format(name))
        api_members.append(name)
    current_app.logger.debug('Full corp roster: ' + ', '.join(api_members))
    for member in Member.query.filter_by(status='Accepted').all():
        if member.character_name not in api_members:
            current_app.logger.warning('-- ' + member.character_name + ' is not in the corporation')
            member.status = 'Left'
            member.corporation = ''
            left_members.append(member.character_name)
            member.hidden = True
    try:
        db.session.commit()
        current_app.logger.info('-- Database saved after member sync')
    except Exception as e:
        current_app.logger.error('-- An error occurred when syncing members: ' + str(e))
    flash('Members imported', 'success')
    return {
        'existing_members': existing_members,
        'new_members': new_members,
        'left_members': left_members
    }


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
    if not current_user.recruiter and not current_user.admin:
        current_app.logger.debug('Visibility access denied to {}'.format(current_user.name))
        return redirect(url_for('.index'))
    members = Member.query.filter(Member.status != 'Left').all()
    member_names = get_all_member_names()
    defunct_alts = []
    invalid_mains = []
    missing_api_keys = []
    for member in members:
        if member.character_name != member.main:
            if member.main not in member_names:
                invalid_mains.append(member)
            else:
                main = [m for m in members if m.character_name == member.main]
                if (len(main) > 0 and main[0].status == 'Left') or not main:
                    defunct_alts.append(member)
        if not member.key_id or not member.v_code:
            missing_api_keys.append(member)
    return render_template('hr/reports.html',
        defunct_alts=defunct_alts, invalid_mains=invalid_mains, missing_api_keys=missing_api_keys)


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
            return redirect(url_for('.index'))
        return redirect(url_for('.join'))
    return redirect(url_for('login'))


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
        return redirect(url_for('.login'))
    current_app.logger.debug('Reddit callback by {}'.format(current_user.name))
    username = reddit_oauth.get_token(request.args['code'])
    get_member_for(current_user).reddit = username
    current_app.logger.info('{} updated their reddit account to {}'.format(current_user.name, username))
    for member in Member.query.filter_by(main=get_member_for(current_user).character_name).all():
        member.reddit = username
        current_app.logger.info('{} updated their alt {} reddit account to {}'.format(
            current_user.name, member.character_name, username
        ))
    db.session.commit()
    return redirect(url_for('.index'))


def api_key_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        """
        Endpoint decorator for REST interactions - the request
        header must contain the secret from the config.

        Args:
            args (tuple) - args
            kwargs (dict) - kwargs

        Returns:
            call of the wrapped method if the header was valid, a
            error 403 response otherwise
        """
        token = request.headers.get('REST-SECRET')
        if not token or not token == app.config['REST_SECRET']:
            current_app.logger.warning('Access denied to API endpoint ' + str(request.endpoint) + ', token = ' + str(token))
            abort(403)
        return f(*args, **kwargs)
    return inner


@app.route('/api/sync')
@api_key_required
def api_sync():
    """
    Syncs the corporation membership with the EVE XML API
    and returns the result of doing so.

    Args:
        None

    Returns:
        response (JSON)
    """
    current_app.logger.info('API endpoint sync accessed')
    return jsonify(sync_members())


@app.route('/api/apps')
@api_key_required
def api_apps():
    """
    Returns a list of all new apps since the last poll.

    Args:
        None

    Returns:
        response (JSON)
    """
    current_app.logger.info('API endpoint apps accessed')
    apps = new_apps
    new_apps.clear()
    return jsonify(apps)


@app.route('/api/keys')
@api_key_required
def api_keys():
    """
    Iterates through all API keys in the database and checks that
    they're still valid. Since API keys are validated when entered
    and cannot be removed from the system without being switched
    for another valid pair, the only way that a user can block
    access to their data through the EVE XML API is deleting the
    key from their account. There's no notification for this, so
    keys have to be checked periodically.

    To reduce the amount of API calls, members who've already
    left the corporation are not checked.

    Args:
        None

    Returns:
        response (JSON)
    """
    current_app.logger.info('API endpoint keys accessed')
    invalid_keys = []
    for member in Member.query.filter(Member.status != 'Left').all():
        try:
            auth = XMLAPI(key=member.key_id, code=member.v_code, user_agent=eveapi['user_agent'])
            result = auth.account.APIKeyInfo()
            if not int(result['key']['@accessMask']) == app.config['API_KEY_MASK']:
                invalid_keys.append(member.character_name)
                current_app.logger.warning('-- ' + member.character_name + ' has an invalid API key!')
            else:
                current_app.logger.debug('-- ' + member.character_name + ' has a valid API key')
        except Exception:
            invalid_keys.append(member.character_name)
            current_app.logger.warning('-- ' + member.character_name + ' has an invalid API key!')
    return jsonify(invalid_keys)


def get_all_member_names():
    """
    Returns a list of all member names in the corporation.

    Args:
        None

    Returns:
        value (list) of string names
    """
    return sorted([m.character_name for m in Member.query.all()], key=lambda x: x.lower())


def get_corp_for_name(name):
    """
    This helper method takes a character's name and returns their EVE character ID.
    Args:
        name (str) - full character name
    Returns:
        value (int) of their EVE character ID
    """
    return get_corp_for_id(eveapi['xml'].eve.CharacterId(names=name)['rowset']['row']['@characterID'])


def get_corp_for_id(id):
    """
    This helper method takes a character's id and returns their corporation name.
    Args:
        name (str) - full character name
    Returns:
        value (str) of their corporation's name
    """
    return eveapi['xml'].eve.CharacterAffiliation(ids=id)['rowset']['row']['@corporationName']


def get_member_for(user):
    if current_user.is_anonymous:
        return None
    return Member.query.filter_by(character_name=user.name).first()
