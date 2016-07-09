from datetime import datetime

from hr.shared import db


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer)
    character_name = db.Column(db.String)

    def __init__(self, character_id, character_name):
        self.character_id = character_id
        self.character_name = character_name

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


class Application(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    character_name = db.Column(db.String)
    applied_date = db.Column(db.DateTime)
    status = db.Column(db.String)
    alts = db.Column(db.String)
    notes = db.Column(db.String)
    hidden = db.Column(db.Boolean)
    api_keys = db.relationship('APIKey', backref='application', lazy='dynamic')

    def __init__(self, name, alts=None, notes=None):
        self.character_name = name
        self.applied_date = datetime.utcnow()
        self.status = 'Applied'
        self.alts = ''
        self.notes = ''
        self.hidden = False

    def __str__(self):
        return '<Application-{}>'.format(self.character_name)


class APIKey(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'))
    key = db.Column(db.String)
    code = db.Column(db.String)

    def __init__(self, application_id, key, code):
        self.application_id = application_id
        self.key = key
        self.code = code

    def __str__(self):
        return '<APIKey-{}>'.format(self.key)
