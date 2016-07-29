from datetime import datetime

from hr.shared import db


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    admin = db.Column(db.Boolean)

    def __init__(self, name, admin=False):
        self.name = name
        self.admin = admin

    @property
    def is_authenticated(self):
        return self.member and (self.admin or self.member.status in ['Member', 'Accepted', 'Recruiter'])

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    @property
    def member(self):
        return Member.query.filter_by(character_name=self.name).first()

    def __str__(self):
        return '<User-{}>'.format(self.name)


class Member(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    character_name = db.Column(db.String)
    corporation = db.Column(db.String)
    reddit = db.Column(db.String)
    date = db.Column(db.DateTime)
    status = db.Column(db.String)
    main = db.Column(db.String)
    notes = db.Column(db.String)
    hidden = db.Column(db.Boolean)
    key_id = db.Column(db.String)
    v_code = db.Column(db.String)

    def __init__(self, character_name, corporation, status='New',
            reddit=None, main=None, notes=None, key_id=None, v_code=None):
        self.character_name = character_name
        self.corporation = corporation
        self.date = datetime.utcnow()
        self.status = status
        self.reddit = reddit
        self.main = main or character_name
        self.notes = notes
        self.key_id = key_id
        self.v_code = v_code
        self.hidden = False

    @property
    def user(self):
        return User.query.filter_by(name=self.character_name).first()

    def __str__(self):
        return '<Member-{}>'.format(self.character_name)
