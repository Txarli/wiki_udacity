import os
import webapp2
import jinja2

import txarlitoudacity

import database

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

class Handler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
  
	def render_str(self, template, **params):
		params['user'] = Handler.session_user
		t = jinja_env.get_template(template)
		return t.render(params)
  
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		Handler.session_user = None
		user_id_cookie = self.request.cookies.get('user_id', 0)
		if (user_id_cookie):
			user_id_hash = user_id_cookie.split('|')[0]
			user_id = user_id_cookie.split('|')[1]
			if txarlitoudacity.check_user_id_hash(user_id_hash, user_id):
				Handler.session_user = database.User.get_by_id(int(user_id))

