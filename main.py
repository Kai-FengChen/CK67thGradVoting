#coding=utf-8
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import webapp2
import re
import jinja2
import sys
import os
sys.path.append(os.path.abspath("./py-bcrypt"))
import bcrypt
import logging
import pdb
import json
import string
import random
from datetime import datetime, timedelta
import sys
import httplib
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

from google.appengine.ext import db
from google.appengine.api import memcache

import urllib, urllib2
#import lxml.html as lh

def validAccount(username, password):

    url = 'https://study.ck.tp.edu.tw/login_chk.asp'
    matching = '<meta'
    form_data = {
        'f_uid': username,
        'f_pwd': password,
        'submit': 'submit',
    }
    
    data = urllib.urlencode(form_data)
    req = urllib2.Request(url, data)
    res = urllib2.urlopen(req)
    #print res.read()
    if( res.read().find(matching) != -1):
        return True
    else:
        return False

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, content):
        json_text = json.dumps(content)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_text)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)
def hashed_user(username, password, secret = None):
    if not secret:
        secret = ''.join(random.SystemRandom().choice(string.ascii_letters) for i in range(random.randrange(5,10)))
        hashed = bcrypt.hashpw(secret+username+password, bcrypt.gensalt())
        return "%s|%s" %(secret,hashed)

def valid_user(username, password, hashed):
    val = hashed.split('|')
    return bcrypt.hashpw(val[0]+username+password, val[1]) == val[1]



class Users(db.Model):
    name = db.StringProperty(required = True)
    vote = db.StringProperty(required = False)
    @classmethod
    def by_id(cls, user_id):
        return Users.get_by_id(user_id, parent = users_key())
    @classmethod
    def by_name(cls, name):
        u = Users.all().ancestor(users_key()).filter('name =', name).get()
        return u
    @classmethod
    def login(cls, username, password):
        user = cls.by_name(username)
        if user and valid_user(username, password, user.pw_hash):
            return user

def hashed_cookie(val):
    hashed = bcrypt.hashpw(val, bcrypt.gensalt())
    return "%s|%s" %(val,hashed)

def valid_hashed(hashed):
    val = hashed.split('|')
    if bcrypt.hashpw(val[0], val[1]) == val[1]:
        return val[0]



USER_RE = re.compile(r"^ck(100|101)\d{4}")
def valid_username(username):
    return USER_RE.match(username)
PASSWORD_RE = re.compile(r"^\d{8}")
def valid_password(password):
    return PASSWORD_RE.match(password)
class MainPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
        self.render("temp.html")
    def post(self):
        have_error = False
        username = self.request.get('username')
        params = dict(username = username)
        if not username:
            have_error = True
            params['error_user'] = '請填入夢駝林帳號!'
        elif not valid_username(username):
            have_error = True
            params.pop("username",None)
            params['error_user'] = '帳號格式錯誤!'
        password = self.request.get('password')
        if not password:
            params['error_password'] = '請輸入身份證字號!'
        try:
            login = validAccount(username,password)
        except httplib.HTTPException:
            have_error = True
            params['login_error'] = '登入失敗!請檢查帳號密碼後重新登入'
        else:
            if login:
                user = Users.by_name(username)
                if user:
                    self.redirect('/Thankyou')
                else:
                    hashed = hashed_cookie(str(username))
                    self.response.headers['Content-Type'] = 'text/plain'
                    self.response.headers.add_header('Set-Cookie','user_id=%s; Path=/' %hashed)
                    self.redirect("/vote")
            else:
                have_error = True
                params['login_error'] = '登入失敗!請檢查帳號密碼後重新登入'
        if have_error == True:
            self.render("temp.html", **params)

class VotePage(Handler):
    def get(self):
        user = None
        hashed_id = self.request.cookies.get('user_id')
        if hashed_id and valid_hashed(hashed_id):
            user = Users.by_name(valid_hashed(hashed_id))
            if not user:
                self.render('Vote.html')
        else:
            self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
            self.redirect('/Thankyou')
    def post(self):
        user = None
        vote = self.request.get('vote')
        hashed_id = self.request.cookies.get('user_id')
        if hashed_id and valid_hashed(hashed_id):
            user = Users(parent = users_key(),
                         name = valid_hashed(hashed_id),
                         vote = vote)
            user.put()
            self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
            self.redirect('/Thankyou')
        else:
            self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
            self.redirect('/')

class ThankyouPage(Handler):
    def get(self):
        self.render('Thankyou.html')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/vote',VotePage),
                               ('/Thankyou',ThankyouPage),
                               ],
                              debug=True)
