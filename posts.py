from users import *

from google.appengine.ext import db

# The Blog data section
# Functions and database classes


def blog_key(name='default'):
    """Sets a key for posts."""
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """The database class for posts data."""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.ReferenceProperty(User)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)
    liked_by = db.ListProperty(str)


class Comment(db.Model):
    """The database class for comments data."""
    post_id = db.IntegerProperty(required=True)
    author = db.ReferenceProperty(User)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
