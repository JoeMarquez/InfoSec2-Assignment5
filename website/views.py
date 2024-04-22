from flask import Blueprint, render_template, request, flash, jsonify, current_app
from flask_login import login_required, current_user
from .models import Key, File
from . import db
import json, os

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Note is too short!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')

    return render_template("home.html", user=current_user)



@views.route('/delete-key', methods=['POST'])
def delete_key():
    key = json.loads(request.data)
    keyId = key['keyId']
    key = Key.query.get(keyId)
    if key:
        if key.user_id == current_user.id:
            db.session.delete(key)
            current_user.num_keys -= 1
            db.session.commit()
    
    return jsonify({})


@views.route('/delete-file', methods=['POST'])
def delete_file():
    file = json.loads(request.data)
    fileId = file['fileId']
    file = File.query.get(fileId)

    if file:

        if file.user_id == current_user.id:
            db.session.delete(file)
            current_user.num_files -= 1

            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
            if os.path.exists(file_path):
                os.remove(file_path)

            db.session.commit()
    
    return jsonify({})





    