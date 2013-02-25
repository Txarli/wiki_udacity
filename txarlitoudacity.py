import webapp2
import json
import time
import logging
import re
import hashlib

from google.appengine.api import memcache

import handler
import database




"""
	Post edition and watching pages:
"""

def get_text(path):
	entries = database.db.GqlQuery("SELECT * FROM Entry")
	for entry in entries:
		if entry.path == path:
			return entry.content
	return ""

def insert_text(path, text):
	entries = database.db.GqlQuery("SELECT * FROM Entry")
	for entry in entries:
		if entry.path == path:
			entry.content = text
			entry.put()
			return						
	e = database.Entry(path = path, content = text)
	e.put()

class WikiPage(handler.Handler):
	def render_post(self, text = "", post_path = "/"):
		self.render("post.html", text = text, post_path = post_path, edit_page = False)
		
	def get(self, post_path):
		text = get_text(post_path)
		if not handler.Handler.session_user or text:
			self.render_post(text, post_path)
		else:
			self.redirect('_edit'+post_path)
			
class EditPage(handler.Handler):

	def render_edit(self, text = "", post_path = "/"):
		self.render("edit.html", text = text, post_path = post_path, edit_page = True)

	def get(self, post_path):
		if handler.Handler.session_user:
			text = get_text(post_path)
			self.render_edit(text, post_path)
		else:
			self.redirect('/')

	def post(self, post_path):
		text = self.request.get("content")
		insert_text(post_path, text)

		self.redirect(post_path)

"""
	User management pages
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASSWORD_RE = re.compile("^.{3,20}$")

def check_email(address):
	return EMAIL_RE.match(address)

def check_username(name):
	return USER_RE.match(name)

def check_password(password):
	return USER_RE.match(password)

def check_verify(password, verify):
	return password == verify

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, password):
	h = hashlib.sha256(name + password).hexdigest()
	return '%s' % h

def get_user(name):
	users = database.db.GqlQuery("SELECT * FROM User")
	for user in users:
		if user.username == name:
			return user
	return None

def valid_user(name, pw):
	user = get_user(name)
	if user and user.password == make_pw_hash(name, pw):
		return True
	else:
		return None
 
def check_user_id_hash(hash, id):
	return hash == hashlib.sha256(id).hexdigest()

def get_user_id(name):
	users = database.db.GqlQuery("SELECT * FROM User")
	for user in users:
		if user.username == name:
			return str(user.key().id())

##### Class to manage the user login
class Login(handler.Handler):
	def write_login(self, login_error=''):
		self.render("login.html", login_error = login_error)
	
	def get(self):
		self.write_login()

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		if valid_user(username, password):
			user_id = get_user_id(username)
			self.response.headers.add_header('Set-Cookie','user_id=%s|%s;path=/' % (hashlib.sha256(user_id).hexdigest(), user_id))
			self.redirect('/')
		else:
			login_error = 'Invalid login'
			self.write_login(login_error)

##### Class to manage the user signup
class Signup(handler.Handler):
	def write_signup(self, 
			username='', username_error='',
			password='', password_error='',
			verify='', verify_error='',
			email='', email_error=''):

		self.render("signup.html", 
			username=username,
			username_error=username_error,
			password=password,
			password_error=password_error,
			verify=verify,
			verify_error=verify_error,
			email=email,
			email_error=email_error)

	def get(self):
		self.write_signup()

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		
		success = True
		
		if(check_username(username)):
			username_error = ""
			users = database.db.GqlQuery("SELECT * FROM User")
			for user in users:
				if username==user.username:
					username_error = "That username is un use."
					success = False
					break
					
		else:
			username_error = "That's not a valid username."
			success = False

		if(check_password(password)):
			password_error = ""
		else:
			password_error = "That wasn't a valid password."
			success = False

		if(check_verify(password, verify)):
			verify_error = ""
		else:
			password_error = ""
			verify_error = "Your passwords didn't match."
			success = False

		if email:
			if(check_email(email)):
				email_error = "" 
			else:
				email_error = "That's not a valid email."
				success = False
		else:
			email_error = ""

		if(success):
			pass_hash = make_pw_hash(username, password)
			u = database.User(username=username, password=pass_hash, email=email)
			u.put()

			user_id = str(u.key().id())
			self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s;path=/' % (hashlib.sha256(user_id).hexdigest(), user_id))
			self.redirect('/')
		else:		
			self.write_signup(username, username_error, password, password_error, verify, verify_error, email, email_error)

#####Class for the logout. It deletes the user cookie
class Logout(handler.Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=;path=/')
		self.redirect('/')


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup/?', Signup),
                               ('/login/?', Login),
                               ('/logout/?', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)
