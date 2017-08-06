import logging
import urllib2
import json
import os
import re
import base64
import hashlib
import uuid
import random
import string

from flask import Flask, flash, render_template, request, session, redirect, url_for, escape
from google.appengine.ext import ndb
from google.appengine.ext.ndb import metadata
from random import choice
from string import digits
from werkzeug.security import generate_password_hash, \
	check_password_hash

class Account(ndb.Model):
    username = ndb.StringProperty()
    hashedpassword = ndb.StringProperty()
    token = ndb.StringProperty()
    isAdmin = ndb.BooleanProperty()

    def HashPassword(self, password):
        #salt = uuid.uuid4().hex
        #hashed_password = hashlib.sha512(password + salt).hexdigest()
        self.hashedpassword = generate_password_hash(password)

    def CheckPassword(self, password):
		return check_password_hash(self.hashPassword, password)

    def NewAccount(cls, name, password, isAdmin):
		user = Account()
		user.username = name
		user.HashPassword(password)
		user.isAdmin = isAdmin
        user.put()
		return user

    def GetPlayerByUserName(cls, name):
		query = Account.query(Account.name == name)
		return query.get()
