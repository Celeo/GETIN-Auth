from .shared import db


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    corporation = db.Column(db.String)
    admin = db.Column(db.Boolean)
    recruiter = db.Column(db.Boolean)
    mentor = db.Column(db.Boolean)
    wiki_mod = db.Column(db.Boolean)

    def __init__(self, name, corporation, admin=False, recruiter=False, mentor=False, wiki_mod=False):
        self.name = name
        self.corporation = corporation
        self.admin = admin
        self.recruiter = recruiter
        self.mentor = mentor
        self.wiki_mod = wiki_mod

    @property
    def is_authenticated(self):
        # TODO fix
        return self.corporation == 'Wormbro'

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __str__(self):
        return '<User-{}>'.format(self.name)
