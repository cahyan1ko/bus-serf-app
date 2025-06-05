from flask_pymongo import PyMongo
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth

mongo = PyMongo()
mail = Mail()
oauth = OAuth()