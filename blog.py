import os
import re
import hmac
import hashlib
import random
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

secret = 'op.y7t5YU$juImsbgt.uu&,P^6280nhf0'  # global for hashing

# defines the template directory and set jinja environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# The Users data section
# Functions, validations and database classes

# The regex validation for user data, using re library
USER_RE = re.compile(r"[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    """Username validation."""
    return username and USER_RE.match(username)


def valid_password(password):
    """Password validation."""
    return password and PASS_RE.match(password)


def valid_email(email):
    """Email validation."""
    return not email or EMAIL_RE.match(email)


def make_secure_val(val):
    """Makes a secure value with hmac library."""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """Checks if value is secure."""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    """Makes salt for password hash."""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """Hash password with hashlib library."""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, pw, h):
    """Validates the hash password."""
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


def users_key(group='default'):
    """Sets a key for users"""
    return db.Key.from_path('users', group)


class User(db.Model):
    """The database class for users data."""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# The Blog data section
# Functions and database classes

def blog_key(name='default'):
    """Sets a key for posts."""
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """The database class for posts data."""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    likes = db.IntegerProperty(default=0)
    author = db.ReferenceProperty(User)
    created = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):
    """The database class for comments data."""
    post_id = db.IntegerProperty(required=True)
    author = db.ReferenceProperty(User)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Like(db.Model):
    """the database class for likes in posts data."""
    post_id = db.IntegerProperty(required=True)
    author = db.ReferenceProperty(User)


# The Handlers section

class Handler(webapp2.RequestHandler):
    """Sets the parent handler for rendering pages and cookies."""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Renders the Jinja template."""
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """Renders tamplate to pages."""
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Sets a cookie."""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Reads a cookie and returns it's value."""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """Sets a cookie for login."""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """Overwrites the cookie with none to stop the user session."""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """Initializes pages with user signed in."""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(Handler):
    """The main page handler."""
    def get(self):
        """Renders front page with posts in desc order."""
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class Signup(Handler):
    """The signup page handler."""
    def get(self):
        """Renders the page."""
        self.render('signup.html')

    def post(self):
        """Validates the user inputs + error messages."""
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username!"
            have_error = True

        if not valid_password(self.password):
            params['password_error'] = "That's not a valid password!"
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "The passwords didn't match!"
            have_error = True

        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email!"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        """ Raises not implemented error."""
        raise NotImplementedError


class Register(Signup):
    """The user registration handler for signup page."""
    def done(self):
        """Checks if username doesn't exists and save data to db."""
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', username_error=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()  # saves user data to database

            self.login(u)
            self.redirect('/welcome')


class Welcome(Handler):
    """The welcome page handler."""
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Login(Handler):
    """The login page handler."""
    def get(self):
        self.render('login.html')

    def post(self):
        """Validates the user login."""
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            error = 'Invalid login. Try again!'
            self.render('login.html', error=error)


class Logout(Handler):
    """The logout handler."""
    def get(self):
        self.logout()
        self.redirect('/signup')


class NewPost(Handler):
    """The handler for creating new posts."""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent=blog_key(), subject=subject, content=content,
                        author=self.user)
            post.put()  # saves post data in database
            self.redirect("/%s" % str(post.key().id()))
        else:
            error = "You need to submit a subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class PostPage(Handler):
    """The single post page handler"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.gql("WHERE post_id = %s ORDER BY created DESC"
                               % int(post_id))
        liked = None

        if self.user:
            liked = Like.gql("WHERE post_id = :1 AND author.name =  :2",
                             int(post_id), self.user.name).get()
        if not post:
            self.error(404)
            return
        self.render("post.html", post=post, comments=comments, liked=liked)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.request.get("like"):
            if self.user and post:
                post.likes += 1
                like = Like(post_id=int(post_id), author=self.user)
                like.put()
                post.put()
                self.redirect("/%s" % post_id)
        elif self.request.get("unlike"):
            if self.user and post:
                post.likes -= 1
                like = Like(post_id=int(post_id), author=self.user)
                db.delete(key)
                post.put()
                self.redirect("/%s" % post_id)
        else:
            content = self.request.get("content")
            if content:
                comment = Comment(content=str(content), author=self.user,
                                  post_id=int(post_id))
                comment.put()
                self.redirect("/%s" % post_id)
            else:
                self.render("post.html", post=post)


class EditPost(Handler):
    """The handler for editing posts."""
    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return
            self.render("editpost.html", subject=post.subject,
                        content=post.content, post=post)
        else:
            self.redirect("/login")

    def post(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and post.author.name == self.user.name:
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect("/")
            else:
                error = "You need to submit a subject and content, please!"
                self.render("editpost.html", subject=subject, content=content,
                            error=error)
        else:
            self.redirect("/")


class DeletePost(Handler):
    """The handler for deleting posts."""
    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return
            self.render("deletepost.html", post=post)
        else:
            self.redirect("/login")

    def post(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and post.author.name == self.user.name:
            db.delete(key)
        self.redirect("/")


class EditComment(Handler):
    """The handler for editing comments on posts."""
    def get(self):
        if self.user:
            comment_id = self.request.get("comment")
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if not comment:
                self.error(404)
                return

            self.render("editcomment.html", content=comment.content,
                        post_id=comment.post_id)
        else:
            self.redirect("/login")

    def post(self):
        comment_id = self.request.get("comment")
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if comment and comment.author.name == self.user.name:
            content = self.request.get("content")

            if content:
                comment.content = content
                comment.put()
                self.redirect("/%s" % comment.post_id)
            else:
                error = "You need to have a text in it!"
                self.render("editcomment.html", content=content,
                            post_id=comment.post_id, error=error)
        else:
            self.redirect("/%s" % comment.post_id)


class DeleteComment(Handler):
    """The handler for deleting comments on posts."""
    def get(self):
        if self.user:
            comment_id = self.request.get("comment")
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if not comment:
                self.error(404)
                return
            self.render("deletecomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        comment_id = self.request.get("comment")
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if comment and comment.author.name == self.user.name:
            post_id = comment.post_id
            db.delete(key)

        self.redirect("/%s" % post_id)


app = webapp2.WSGIApplication([
    ('/?', MainPage),
    ('/([0-9]+)', PostPage),
    ('/newpost', NewPost),
    ('/editpost', EditPost),
    ('/deletepost', DeletePost),
    ('/comment/edit', EditComment),
    ('/comment/delete', DeleteComment),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome),
], debug=True)
