from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    firstName = db.Column(db.String(150))
    num_keys = db.Column(db.Integer, default=0)
    num_files = db.Column(db.Integer, default=0)

    # TODO: Remember to delete notes
    notes = db.relationship('Note')

    keys = relationship('Key', back_populates='user')
    files = relationship('File', back_populates='user')
    hashes = relationship('Hash', back_populates='user')

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    key_value = db.Column(db.String(255))

    user = relationship('User', back_populates='keys')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(255))
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    upload_timestamp = db.Column(db.DateTime(timezone=True), default=func.now())
    content = db.Column(db.LargeBinary)

    hashes = relationship('Hash', back_populates='file')
    user = relationship('User', back_populates='files')

class Hash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    hash_value = db.Column(db.String(255))
    hash_algorithm = db.Column(db.String(50))

    file = relationship('File', back_populates='hashes')
    user = relationship('User', back_populates='hashes')    
