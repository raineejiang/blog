import os
import re
from string import letters
import webapp2
import jinja2
import hmac
import random
import string
import hashlib
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#Here comes the sign-up part
#regular expression
SECRET = "kevin"

#Hashing username
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

#Hashing password
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h.split(',')[0] == hashlib.sha256(name + pw + salt).hexdigest()

#Define valid expressions for username, passowrd and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Define the Users class in db to store user-related information
class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required=False)

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('username =', name).get()
        return u

# Define the Blogs class in db to store blog-related information
class Blogs(db.Model, BaseHandler):
    subject = db.StringProperty(required = True)
    blog = db.TextProperty(required = True)
    author = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.blog.replace('\n', '<br>')
        return self.render_str("blog.html", b = self)

#The main page to display all the posts
class MainPage(BaseHandler):
    def get(self):
        blogs = db.GqlQuery("select * from Blogs order by created desc limit 10")
        self.render("mainpage.html", blogs=blogs)

    def post(self):
        comment = self.request.get("comment")
        self.redirect('/blog/newcomment/([0-9]+)')




#The page to put in information about a new post
class Newpost(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        blog = self.request.get("blog")

        username_cookie_str = self.request.cookies.get('username')
        username=None
        if username_cookie_str:
            cookie_val = check_secure_val(username_cookie_str)
            if cookie_val:
                username = cookie_val

        author = username

        if subject and blog and author:
            b = Blogs(subject=subject, blog=blog, author=author)
            b.put()
            id = b.key().id()
            self.redirect('/blog/%s' % str(id))
        elif not author:
            error="login first, please!"
            self.render("newpost.html", subject=subject, blog=blog, error=error)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, blog=blog, error=error)

#The page to display the newly created post
class Singlepost(BaseHandler):
    def get(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        if not post:
            self.error(404)
        self.render("singlepost.html", post=post)

#Sign up page
class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        u = Users.by_name(str(make_secure_val(username)))

        if u:
            params['error_username'] = "That user already exists"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            username_cookie_val = str(make_secure_val(username))
            password_val=make_pw_hash(username, password)
            u = Users(username=username_cookie_val, password=password_val, email=email)
            u.put()
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % username_cookie_val)
            self.redirect('/blog/welcome')

#Log in page
class Login(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = Users.by_name(str(make_secure_val(username)))
        if u:
            password_val = u.password
            username_cookie_val = u.username
            if valid_pw(username, password, password_val):
                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % str(username_cookie_val))
                self.redirect('/blog/welcome')
            else:
                self.render("login.html", error_message="Invalid login")
        else:
            self.render("login.html", error_message="Invalid login")

#Welcome page
class Welcome(BaseHandler):
    def get(self):
        username_cookie_str = self.request.cookies.get('username')
        username=None
        if username_cookie_str:
            cookie_val = check_secure_val(username_cookie_str)
            if cookie_val:
                username = cookie_val
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

#Newcomment page
class Newcomment(BaseHandler):
    def get(self, post_id):
        self.render("newcomment.html")

class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect ('/blog/signup')


app = webapp2.WSGIApplication([
    ('/blog', MainPage),
    ('/blog/newpost', Newpost),
    ('/blog/([0-9]+)', Singlepost),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
    ('/blog/logout', Logout),
    ('/blog/newcomment/([0-9]+)', Newcomment),
    ('/blog/login', Login)],
    debug=True)


