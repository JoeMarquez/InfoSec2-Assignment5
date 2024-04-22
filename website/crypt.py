from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, send_from_directory
from .models import *
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random, string, os, hashlib, base64


crypt = Blueprint('crypt', __name__)

class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File")

@crypt.route('/generate_keys', methods=['POST','GET'])
@login_required
def generate_keys():
    if request.method == 'POST':
        if current_user.num_keys < 20:

            key = Fernet.generate_key()

            new_key = Key(user_id=current_user.id, key_value=key)
            db.session.add(new_key)

            current_user.num_keys += 1
            db.session.commit()

            return redirect(url_for('crypt.generate_keys'))
        else:
            flash("Sorry, you can't generate anymore keys.", category='error')
            return redirect(url_for('crypt.generate_keys'))

    return render_template('generate_keys.html', user=current_user)

MAX_FILES_PER_USER = 8
MAX_FILE_SIZE_MB = 1 

@crypt.route('/upload_files', methods=['POST', 'GET'])
@login_required
def upload_files():
    if request.method == 'POST':

        if current_user.num_files >= MAX_FILES_PER_USER:
            flash('You have reached the maximum number of files allowed.', category='error')
            return redirect(url_for('crypt.upload_files'))

        files = request.files.getlist('file')
        for file in files:

            if file.content_length > MAX_FILE_SIZE_MB * 1024 * 1024:
                flash('File size exceeds the limit.', category='error')
                return redirect(url_for('crypt.upload_files'))

            upload_folder = current_app.config['UPLOAD_FOLDER']
            file_path = os.path.join(upload_folder, secure_filename(file.filename))
            file.save(file_path)

            if current_user.is_authenticated:
                new_file = File(filename=file.filename, user_id=current_user.id)
                db.session.add(new_file)
                current_user.num_files += 1
                db.session.commit()

        flash('Files uploaded successfully!', category='success')
        return redirect(url_for('crypt.upload_files'))

    user_files = File.query.filter_by(user_id=current_user.id).all()

    return render_template('file_management.html', user=current_user, user_files=user_files)


@crypt.route('/uploads/<path:filename>', methods=['GET'])
@login_required
def download_file(filename):
    if current_user.is_authenticated:
        file_path = os.path.join(os.path.abspath(current_app.config['UPLOAD_FOLDER']), filename)

        if os.path.exists(file_path):
            return send_from_directory("uploads", filename, as_attachment=True)
        else:
            flash("File not found!", category='error')

    else:
        flash("You need to be logged in to download files.", category='error')
    return redirect(url_for('crypt.upload_files'))


@login_required
@crypt.route('/hash_files', methods=['POST', 'GET'])
def hash_file():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    if request.method == 'POST':

        if current_user.is_authenticated:
            data = request.get_json()
            filename = data['filename']
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(65536) 
                    if not data:
                        break
                    hasher.update(data)
            file_hash = hasher.hexdigest()
            return file_hash

    return render_template('hash_files.html', user=current_user, user_files=user_files)

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    return base64.b64encode(encrypted_data).decode()

@login_required
@crypt.route('/encrypt', methods=['POST','GET'])
def encrypt():

    user_files = File.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        
        data = request.form.get('data')
        key = request.form.get('key')
        encrypted_data = encrypt_aes(data, key)

    return render_template('encrypt_decrypt.html', user=current_user, user_files=user_files)

