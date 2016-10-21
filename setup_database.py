#!/usr/bin/env python
from auth.app import db
from auth.models import *
from auth.hr.models import *
from auth.wiki.models import *
from auth.ecm.models import *
from auth.hauling.models import *


db.drop_all()
db.create_all()
u = User('Celeo Servasse', 'Wormbro', True, True, True, True)
db.session.add(u)
ns = Namespace('public')
db.session.add(ns)
ns2 = Namespace('private', True)
db.session.add(ns2)
r = Revision(1, 1, 'Index page')
db.session.add(r)
p = Page(1, 'Index', 'Index page')
db.session.add(p)
db.session.commit()
