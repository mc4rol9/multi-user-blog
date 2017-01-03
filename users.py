import re
import hmac
import hashlib
import random
from string import letters

from google.appengine.ext import db

secret = 'op.y7t5YU$juImsbgt.uu&,P^6280nhf0'  # global for hashing

# The Users data
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
