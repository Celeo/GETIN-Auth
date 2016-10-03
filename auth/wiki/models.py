from datetime import datetime

from auth.shared import db
from auth.models import User


class Namespace(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    private = db.Column(db.Boolean)
    pages = db.relationship('Page', backref='namespace', lazy='dynamic')

    def __init__(self, name, private=False):
        self.name = name.strip(':')
        self.private = private

    def __str__(self):
        return '<Namespace-{}>'.format(self.name)


class Page(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    namespace_id = db.Column(db.Integer, db.ForeignKey('namespace.id'))
    name = db.Column(db.String)
    contents = db.Column(db.String)
    approved = db.Column(db.Boolean)
    revisions = db.relationship('Revision', backref='page', lazy='dynamic')

    def __init__(self, namespace_id, name, contents=''):
        self.namespace_id = namespace_id
        self.name = name
        self.contents = contents

    @property
    def private(self):
        return self.namespace.private

    @property
    def path(self):
        return self.namespace.name + ':' + self.name

    def __str__(self):
        return '<Page-{}>'.format(self.name)


class Revision(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    contents = db.Column(db.String)
    date = db.Column(db.DateTime)

    def __init__(self, page_id, user_id, contents):
        self.page_id = page_id
        self.user_id = user_id
        self.contents = contents
        self.date = datetime.utcnow()

    @property
    def user(self):
        return User.query.get(self.user_id)

    def __str__(self):
        return '<Revision-{}>'.format(self.page_id)
