import os

import webapp2
import jinja2

from users import *  # import modele for users data: functions and db classes
from posts import *  # import module for posts data: functions and db classes

from google.appengine.ext import db

# defines the template directory and set jinja environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


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
            return self.redirect('/login')

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
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = %s ORDER BY created DESC"
                               % int(post_id))
        liked = False

        if self.user:
            if post.author == self.user.name or self.user.name in post.liked_by:
                liked = True

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
                post.liked_by.append(self.user.name)
                post.put()
                self.redirect("/%s" % post_id)
        elif self.request.get("unlike"):
            if self.user and post:
                post.likes -= 1
                post.liked_by.remove(self.user.name)
                post.put()
                self.redirect("/%s" % post_id)
        else:
            if not self.user:
                return self.redirect('/login')
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
