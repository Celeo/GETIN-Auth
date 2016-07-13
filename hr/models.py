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
        return self.member and self.member.status in ['Member', 'Accepted', 'Recruiter']

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
    api_keys = db.relationship('APIKey', backref='member', lazy='dynamic')

    def __init__(self, character_name, corporation, status='New', reddit=None, main=None, notes=None):
        self.character_name = character_name
        self.corporation = corporation
        self.date = datetime.utcnow()
        self.status = status
        self.reddit = reddit
        self.main = main or character_name
        self.notes = notes
        self.hidden = False

    def set_api_keys(self, keys):
        APIKey.query.filter_by(member_id=self.id).delete()
        for line in keys:
            keyID, vCode = line.strip().split(' - ')
            db.session.add(APIKey(self.id, keyID, vCode))
        db.session.commit()

    def get_keys(self):
        return '\n'.join(['{} - {}'.format(key.key, key.code) for key in self.api_keys.all()])

    @property
    def user(self):
        return User.query.filter_by(name=self.character_name).first()

    def __str__(self):
        return '<Member-{}>'.format(self.character_name)


class APIKey(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'))
    key = db.Column(db.String)
    code = db.Column(db.String)

    def __init__(self, member_id, key, code):
        self.member_id = member_id
        self.key = key
        self.code = code

    def __str__(self):
        return '<APIKey-{}>'.format(self.key)
