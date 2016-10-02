#!/usr/bin/env python
from auth.app import db
from auth.models import *
from auth.hr.models import *
from auth.wiki.models import *
from auth.ecm.models import *
from auth.hauling.models import *


db.create_all()
