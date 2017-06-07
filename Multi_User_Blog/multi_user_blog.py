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
import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


SECRET = "kevin"

# Hashing username


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# Hashing password


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h.split(',')[0] == hashlib.sha256(name + pw + salt).hexdigest()

# Define valid expressions for username, passowrd and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Define the Users class in db to store user-related information


class Users(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('username =', name).get()
        return u


# This global method checks whether the use has logged
# in and whether the cookie info is correct
def check_user(self):
    username_cookie_str = self.request.cookies.get('username')
    username = None
    if username_cookie_str:
        cookie_val = check_secure_val(username_cookie_str)
        if cookie_val:
            username = cookie_val
    return username


# Define the Blogs class in db to store blog-related information
class Blogs(db.Model, BaseHandler):
    subject = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    likes = db.ListProperty(int, required=True, default=None)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.blog.replace('\n', '<br>')
        return self.render_str("blog.html", b=self)


# Define the Comments class in db to store comment-related information
class Comments(db.Model, BaseHandler):
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str("comment.html", c=self)


# The main page to display all the posts
class MainPage(BaseHandler):
    def get(self):
        blogs = db.GqlQuery("select * from Blogs" +
                            " order by created desc limit 10")
        comments = db.GqlQuery("select * from Comments")
        self.render("mainpage.html", blogs=blogs, Comments=Comments)


# The page to put in information about a new post
class Newpost(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        author = check_user(self)
        if subject and blog and author:
            b = Blogs(subject=subject, blog=blog, author=author)
            b.put()
            id = b.key().id()
            self.redirect('/blog/%s' % str(id))
        elif not author:
            error = "login first, please!"
            self.render("newpost.html", subject=subject,
                        blog=blog, error=error)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        blog=blog, error=error)


# The page to display the newly created post
class Singlepost(BaseHandler):
    def get(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        if not post:
            self.error(404)
        self.render("singlepost.html", post=post)


# Sign up page
class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

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
            password_val = make_pw_hash(username, password)
            u = Users(username=username_cookie_val,
                      password=password_val, email=email)
            u.put()
            self.response.headers.add_header('Set-Cookie',
                                             'username=%s; Path=/'
                                             % username_cookie_val)
            self.redirect('/blog/welcome')


# Log in page
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
                self.response.headers.add_header('Set-Cookie',
                                                 'username=%s; Path=/'
                                                 % str(username_cookie_val))
                self.redirect('/blog/welcome')
            else:
                self.render("login.html", error_message="Invalid login")
        else:
            self.render("login.html", error_message="Invalid login")


# Welcome page
class Welcome(BaseHandler):
    def get(self):
        username_cookie_str = self.request.cookies.get('username')
        username = None
        if username_cookie_str:
            cookie_val = check_secure_val(username_cookie_str)
            if cookie_val:
                username = cookie_val
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')


# Newcomment page
class Newcomment(BaseHandler):
    def post(self, post_id):
        comment = self.request.get("comment")
        post = Blogs.get_by_id(int(post_id))
        author = check_user(self)
        if not author:
            blogs = db.GqlQuery("select * from Blogs order" +
                                " by created desc limit 10")
            self.render("mainpage.html", error_message="Login first please!",
                        blogs=blogs, Comments=Comments)
        else:
            c = Comments(parent=post, content=comment, author=author)
            c.put()
            self.redirect('/blog')


# Likes page
class Likepost(BaseHandler):
    def get(self, post_id):
        self.render('likes.html')

    def post(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        author = check_user(self)
        username_cookie_str = self.request.cookies.get('username')
        u = Users.by_name(username_cookie_str)
        if not author:
            self.render("likes.html", error_message="Login first please!")
        elif author == post.author:
            self.render("likes.html", error_message="Sorry, " +
                        "but you cannot like your own post.")
        elif int(u.key().id()) in post.likes:
            self.render("likes.html", error_message="Sorry, " +
                        "but you can only like the same post once.")
        else:
            post.likes.append(u.key().id())
            post.put()
            time.sleep(1)
            self.redirect('/blog')


# Dislikes page
class Unlikepost(BaseHandler):
    def get(self, post_id):
        self.render('unlikes.html')

    def post(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        author = check_user(self)
        username_cookie_str = self.request.cookies.get('username')
        u = Users.by_name(username_cookie_str)
        if not author:
            self.render("unlikes.html", error_message="Login first please!")
        elif author == post.author:
            self.render("unlikes.html", error_message="Sorry, " +
                        "but you cannot unlike your own post.")
        elif int(u.key().id()) not in post.likes:
            self.render("unlikes.html", error_message="Sorry, but you " +
                        "can only unlike the post that you have liked.")
        else:
            post.likes.remove(u.key().id())
            post.put()
            time.sleep(1)
            self.redirect('/blog')


# Editpost page
class Editpost(BaseHandler):
    def get(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        subject = post.subject
        content = post.blog
        self.render('editpost.html', subject=subject, blog=content)

    def post(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        author = check_user(self)
        if not author:
            error = "login first, please!"
            self.render("editpost.html",
                        subject=subject, blog=blog, error=error)
        elif author != post.author:
            self.render("editpost.html", subject=subject, blog=blog,
                        error="Sorry, but you can only edit your own post.")
        elif subject and blog and author:
            post = Blogs.get_by_id(int(post_id))
            post.subject = subject
            post.blog = blog
            post.put()
            id = post.key().id()
            self.redirect('/blog/%s' % str(id))
        else:
            error = "subject and content, please!"
            self.render("editpost.html",
                        subject=subject, blog=blog, error=error)


# Deletepost page
class Deletepost(BaseHandler):
    def get(self, post_id):
        self.render('deletepost.html')

    def post(self, post_id):
        blogs = db.GqlQuery("select * from Blogs order" +
                            " by created desc limit 10")
        post = Blogs.get_by_id(int(post_id))
        author = check_user(self)
        if not author:
            self.render("deletepost.html",
                        error_message="Login first please!")
        elif author != post.author:
            self.render("deletepost.html",
                        error_message="Sorry, " +
                        "but you can only delete your own post.")
        else:
            post.delete()
            time.sleep(1)
            self.redirect('/blog')


# This allows users to log out and get redirected to the signup page
class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect('/blog/signup')


app = webapp2.WSGIApplication([
    ('/blog', MainPage),
    ('/blog/newpost', Newpost),
    ('/blog/([0-9]+)', Singlepost),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
    ('/blog/logout', Logout),
    ('/blog/newcomment/([0-9]+)', Newcomment),
    ('/blog/deletepost/([0-9]+)', Deletepost),
    ('/blog/editpost/([0-9]+)', Editpost),
    ('/blog/likes/([0-9]+)', Likepost),
    ('/blog/unlikes/([0-9]+)', Unlikepost),
    ('/blog/login', Login)],
    debug=True)
