from datetime import datetime

from hr.shared import db


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    admin = db.Column(db.Boolean)
    recruiter = db.Column(db.Boolean)
    mentor = db.Column(db.Boolean)

    def __init__(self, name, admin=False):
        self.name = name
        self.admin = admin

    @property
    def is_authenticated(self):
        return self.member and (self.admin or self.recruiter or self.mentor or self.member.status in ['Member', 'Accepted'])

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
    know_good_fits = db.Column(db.Boolean)
    know_scan = db.Column(db.Boolean)
    know_mass_and_time = db.Column(db.Boolean)
    know_organize_gank = db.Column(db.Boolean)
    know_when_to_pve = db.Column(db.Boolean)
    know_comms = db.Column(db.Boolean)
    know_appropriate_ships = db.Column(db.Boolean)
    know_intel = db.Column(db.Boolean)
    know_pvp = db.Column(db.Boolean)
    know_doctrine = db.Column(db.Boolean)

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
        self.know_good_fits = False
        self.know_scan = False
        self.know_mass_and_time = False
        self.know_organize_gank = False
        self.know_when_to_pve = False
        self.know_comms = False
        self.know_appropriate_ships = False
        self.know_intel = False
        self.know_pvp = False
        self.know_doctrine = False

    @property
    def user(self):
        return User.query.filter_by(name=self.character_name).first()

    def get_alts(self):
        return Member.query.filter(Member.main == self.character_name).filter(Member.character_name != self.character_name).all()

    def get_alt_names(self):
        return [alt.character_name for alt in self.get_alts()]

    def __str__(self):
        return '<Member-{}>'.format(self.character_name)
