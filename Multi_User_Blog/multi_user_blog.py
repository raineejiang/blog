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

SECRET = "kevin"


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Users(db.Model):
    """Define the Users class in db to store user-related information"""
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('username =', name).get()
        return u


class Blogs(db.Model, BaseHandler):
    """Define the Blogs class in db to store blog-related information"""
    subject = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    author = db.StringProperty(required=False)
    likes = db.ListProperty(int, required=True, default=None)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.blog.replace('\n', '<br>')
        return self.render_str("blog.html", b=self)


class Comments(db.Model, BaseHandler):
    """Define the Comments class in db to store comment-related information"""
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str("comment.html", c=self)


class HashUser():
    """Hashing username"""
    @classmethod
    def hash_str(cls, s):
        return hmac.new(SECRET, s).hexdigest()

    @classmethod
    def make_secure_val(cls, s):
        return "%s|%s" % (s, cls.hash_str(s))

    @classmethod
    def check_secure_val(cls, h):
        val = h.split('|')[0]
        if h == cls.make_secure_val(val):
            return val


class HashPassword():
    """Hashing password"""
    @classmethod
    def make_salt(cls):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    @classmethod
    def make_pw_hash(cls, name, pw):
        salt = cls.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

    @classmethod
    def valid_pw(cls, name, pw, h):
        salt = h.split(',')[1]
        return h.split(',')[0] == hashlib.sha256(name + pw + salt).hexdigest()


class Validate():
    """Define valid expressions for username, passowrd and email"""
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

    @classmethod
    def valid_username(cls, username):
        return username and cls.USER_RE.match(username)

    @classmethod
    def valid_password(cls, password):
        return password and cls.PASS_RE.match(password)

    @classmethod
    def valid_email(cls, email):
        return not email or cls.EMAIL_RE.match(email)

    @classmethod
    def check_user(cls, self):
        """This method checks whether the user has logged
        in and whether the cookie info is correct"""
        username_cookie_str = self.request.cookies.get('username')
        username = None
        if username_cookie_str:
            cookie_val = HashUser.check_secure_val(username_cookie_str)
            if cookie_val:
                if Users.by_name(username_cookie_str):
                    username = cookie_val
        return username


class MainPage(BaseHandler):
    """The main page to display all the posts"""
    def get(self):
        blogs = db.GqlQuery("select * from Blogs" +
                            " order by created desc limit 10")
        comments = db.GqlQuery("select * from Comments")
        logged = Validate.check_user(self)
        self.render("mainpage.html", blogs=blogs,
                    Comments=Comments, logged=logged)


class Newpost(BaseHandler):
    """The page to put in information about a new post"""
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        author = Validate.check_user(self)
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


class Singlepost(BaseHandler):
    """The page to display the newly created post"""
    def get(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        if not post:
            self.error(404)
        self.render("singlepost.html", post=post)


class Signup(BaseHandler):
    """Sign up page"""
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

        if not Validate.valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not Validate.valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not Validate.valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        u = Users.by_name(str(HashUser.make_secure_val(username)))

        if u:
            params['error_username'] = "That user already exists"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            username_cookie_val = str(HashUser.make_secure_val(username))
            password_val = HashPassword.make_pw_hash(username, password)
            u = Users(username=username_cookie_val,
                      password=password_val, email=email)
            u.put()
            self.response.headers.add_header('Set-Cookie',
                                             'username=%s; Path=/'
                                             % username_cookie_val)
            self.redirect('/blog/welcome')


class Login(BaseHandler):
    """Log in page"""
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = Users.by_name(str(HashUser.make_secure_val(username)))
        if u:
            password_val = u.password
            username_cookie_val = u.username
            if HashPassword.valid_pw(username, password, password_val):
                self.response.headers.add_header('Set-Cookie',
                                                 'username=%s; Path=/'
                                                 % str(username_cookie_val))
                self.redirect('/blog/welcome')
            else:
                self.render("login.html", error_message="Invalid login")
        else:
            self.render("login.html", error_message="Invalid login")


class Welcome(BaseHandler):
    """Welcome page"""
    def get(self):
        username = Validate.check_user(self)
        if Validate.valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')


class Newcomment(BaseHandler):
    """Newcomment page"""
    def post(self, post_id):
        comment = self.request.get("comment")
        post = Blogs.get_by_id(int(post_id))
        author = Validate.check_user(self)
        if not author:
            blogs = db.GqlQuery("select * from Blogs order" +
                                " by created desc limit 10")
            self.render("mainpage.html", error_message="Login first please!",
                        blogs=blogs, Comments=Comments)
        else:
            c = Comments(parent=post, content=comment, author=author)
            c.put()
            self.redirect('/blog')


class Likepost(BaseHandler):
    """Likes page"""
    def get(self, post_id):
        self.render('likes.html')

    def post(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        author = Validate.check_user(self)
        username_cookie_str = self.request.cookies.get('username')
        u = Users.by_name(username_cookie_str)
        if not author:
            self.render("likes.html", error_message="Login first please!")
        elif post is None:
            self.render("likes.html", error_message="Sorry, " +
                        "but the post no longer exists.")
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


class Unlikepost(BaseHandler):
    """Dislikes page"""
    def get(self, post_id):
        self.render('unlikes.html')

    def post(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        author = Validate.check_user(self)
        username_cookie_str = self.request.cookies.get('username')
        u = Users.by_name(username_cookie_str)
        if not author:
            self.render("unlikes.html", error_message="Login first please!")
        elif post is None:
            self.render("unlikes.html", error_message="Sorry, " +
                        "but the post no longer exists.")
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


class Editpost(BaseHandler):
    """Editpost page"""
    def get(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        subject = post.subject
        content = post.blog
        self.render('editpost.html', subject=subject, blog=content)

    def post(self, post_id):
        post = Blogs.get_by_id(int(post_id))
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        author = Validate.check_user(self)
        if not author:
            error = "login first, please!"
            self.render("editpost.html",
                        subject=subject, blog=blog, error=error)
        elif post is None:
            self.render("editpost.html", error_message="Sorry, " +
                        "but the post no longer exists.")
        elif author != post.author:
            self.render("editpost.html", subject=subject, blog=blog,
                        error="Sorry, but you can only edit your own post.")
        elif subject and blog:
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


class Deletepost(BaseHandler):
    """Deletepost page"""
    def get(self, post_id):
        self.render('deletepost.html')

    def post(self, post_id):
        blogs = db.GqlQuery("select * from Blogs order" +
                            " by created desc limit 10")
        post = Blogs.get_by_id(int(post_id))
        author = Validate.check_user(self)
        if not author:
            self.render("deletepost.html",
                        error_message="Login first please!")
        elif post is None:
            self.render("deletepost.html", error_message="Sorry, " +
                        "but the post no longer exists.")
        elif author != post.author:
            self.render("deletepost.html",
                        error_message="Sorry, " +
                        "but you can only delete your own post.")
        else:
            post.delete()
            time.sleep(1)
            self.redirect('/blog')


class Editcomment(BaseHandler):
    """Edit comment page"""
    def get(self, post_id, comment_id):
        post = Blogs.get_by_id(int(post_id))
        comment = Comments.get_by_id(int(comment_id), parent=post)
        content = comment.content
        self.render('editcomment.html', comment=content)

    def post(self, post_id, comment_id):
        post = Blogs.get_by_id(int(post_id))
        comment = Comments.get_by_id(int(comment_id), parent=post)
        content = self.request.get("comment")
        author = Validate.check_user(self)
        if not author:
            self.render("editcomment.html",
                        comment=content,
                        error="login first, please!")
        elif post is None:
            self.render("editcomment.html",
                        comment=content,
                        error="Sorry, " +
                        "but the post no longer exists.")
        elif comment is None:
            self.render("editcomment.html",
                        comment=content,
                        error="Sorry, " +
                        "but the comment no longer exists.")
        elif author != comment.author:
            self.render("editcomment.html",
                        comment=content,
                        error="Sorry, " +
                        "but you can only edit your own comment.")
        elif not content:
            self.render("editcomment.html",
                        comment=content,
                        error="comment content please!")
        else:
            comment.content = content
            comment.put()
            self.redirect('/blog')


class Deletecomment(BaseHandler):
    """Delete comment page"""
    def get(self, post_id, comment_id):
        self.render('deletecomment.html')

    def post(self, post_id, comment_id):
        post = Blogs.get_by_id(int(post_id))
        comment = Comments.get_by_id(int(comment_id), parent=post)
        author = Validate.check_user(self)
        if not author:
            self.render("deletecomment.html",
                        error="login first, please!")
        elif post is None:
            self.render("deletecomment.html",
                        error="Sorry, " +
                        "but the post no longer exists.")
        elif comment is None:
            self.render("deletecomment.html",
                        error="Sorry, " +
                        "but the comment no longer exists.")
        elif author != comment.author:
            self.render("deletecomment.html",
                        error="Sorry, " +
                        "but you can only delete your own comment.")
        else:
            comment.delete()
            time.sleep(1)
            self.redirect('/blog')


class Logout(BaseHandler):
    """This allows users to log out and get redirected to the signup page"""
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
    ("/blog/([0-9]+)/editcomment/([0-9]+)", Editcomment),
    ("/blog/([0-9]+)/deletecomment/([0-9]+)", Deletecomment),
    ('/blog/unlikes/([0-9]+)', Unlikepost),
    ('/blog/login', Login)],
    debug=True)
