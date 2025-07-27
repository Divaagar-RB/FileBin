import os
import uuid
import io
import zipfile
import shutil
from flask import send_file
from flask import Blueprint, request, jsonify, send_from_directory, current_app
from werkzeug.utils import secure_filename
from filebin_clone.backend.models import Bin, File
from filebin_clone.backend.extensions import db
from hashids import Hashids
from flask_jwt_extended import jwt_required, get_jwt_identity


hashids = Hashids(salt="divaagar_secret_code", min_length=8)

bp = Blueprint('api', __name__)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '..', 'uploads')

def generate_bin_id():
    return uuid.uuid4().hex[:8]
@bp.route('/upload', methods=['POST'])

@jwt_required()
def upload_file():
    user_id = get_jwt_identity()
 
    uploaded_files = request.files.getlist('file')

    if not uploaded_files or all(f.filename == '' for f in uploaded_files):
        return jsonify({'error': 'No file(s) selected'}), 400

    # Step 1: Create bin object to get auto-increment ID
    new_bin = Bin(user_id=user_id,bin_id="temp")  # temporary bin_id initially
    db.session.add(new_bin)
    db.session.flush()  # get new_bin.id without committing

    # Step 2: Obfuscate the ID
    obfuscated_id = hashids.encode(new_bin.id)
    new_bin.bin_id = obfuscated_id

    # Step 3: Save each file
    bin_dir = os.path.join(UPLOAD_DIR, obfuscated_id)
    os.makedirs(bin_dir, exist_ok=True)

    for file in uploaded_files:
        if file.filename == '':
            continue  # skip empty files

        filename = secure_filename(file.filename)
        file_path = os.path.join(bin_dir, filename)
        file.save(file_path)

        # Save file metadata in DB
        new_file = File(
            bin_id=obfuscated_id,
            filename=filename,
            filepath=file_path
        )
        db.session.add(new_file)

    db.session.commit()
    return jsonify({
    'bin_id': obfuscated_id,
    'file_url': f'/bin/{obfuscated_id}',
    'user_id': new_bin.user_id   # ✅ Add this
}), 201

from flask_jwt_extended import jwt_required, get_jwt_identity

@bp.route('/bin/<bin_id>/upload', methods=['POST'])
@jwt_required()
def upload_to_existing_bin(bin_id):
    user = get_jwt_identity()  # e.g., user_id
    bin_entry = Bin.query.filter_by(bin_id=bin_id).first()

    if not bin_entry:
        return jsonify({'error': 'Bin not found'}), 404

    # Check that current user is the owner
    if int(bin_entry.user_id) != int(user):
        return jsonify({'error': 'Unauthorized'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    files = request.files.getlist('file')
    if not files:
        return jsonify({'error': 'No files found in request'}), 400

    bin_dir = os.path.join(UPLOAD_DIR, bin_id)
    os.makedirs(bin_dir, exist_ok=True)

    saved_files = []
    for file in files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        filepath = os.path.join(bin_dir, filename)
        file.save(filepath)

        new_file = File(
            bin_id=bin_id,
            filename=filename,
            filepath=filepath
        )
        db.session.add(new_file)
        saved_files.append(filename)

    db.session.commit()

    return jsonify({
        'message': f'{len(saved_files)} file(s) added to bin {bin_id}',
        'files': saved_files
    }), 201

@bp.route('/bin/<bin_id>', methods=['GET'])
def get_bin_files(bin_id):
    bin = Bin.query.filter_by(bin_id=bin_id).first()
    if not bin:
        return jsonify({'error': 'Bin not found'}), 404

   
    files = [{
        'filename': f.filename,
        'download_url': f'/bin/{bin_id}/download/{f.filename}',
        'delete_url': f'/bin/{bin_id}/file/{f.filename}'
    } for f in bin.files]

    return jsonify({
        'bin_id': bin_id,
        'user_id': bin.user_id,  # ✅ Add this line
        'files': files
    })

from flask import send_from_directory, abort

@bp.route('/bin/<bin_id>/download/<filename>', methods=['GET'])
def download_file(bin_id, filename):
    bin_path = os.path.join(UPLOAD_DIR, bin_id)

    try:
        return send_from_directory(
            directory=bin_path,
            path=filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404


@bp.route('/bin/<bin_id>/download_all', methods=['GET'])
def download_all_files(bin_id):
    bin_path = os.path.join(UPLOAD_DIR, bin_id)

    if not os.path.exists(bin_path):
        return jsonify({'error': 'Bin not found'}), 404

    # Create in-memory zip
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for filename in os.listdir(bin_path):
            file_path = os.path.join(bin_path, filename)
            zipf.write(file_path, arcname=filename)  # arcname avoids full path in zip

    memory_file.seek(0)

    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{bin_id}.zip'
    )


@bp.route('/bin/<bin_id>/file/<filename>', methods=['DELETE'])
@jwt_required()
def delete_file(bin_id, filename):
    # Step 1: Find file entry
    user = get_jwt_identity()
    
    bin_entry = Bin.query.filter_by(bin_id=bin_id).first()
    if int(bin_entry.user_id) != int(user):
        return jsonify({'error': 'Unauthorized'}), 403
    
    if not bin_entry:
        return jsonify({'error': 'Bin not found'}), 404

    

    file_entry = File.query.filter_by(bin_id=bin_id, filename=filename).first()
    if not file_entry:
        return jsonify({'error': 'File not found in this bin'}), 404

    # Step 2: Delete file from disk
    if os.path.exists(file_entry.filepath):
        os.remove(file_entry.filepath)

    # Step 3: Delete file record from DB
    db.session.delete(file_entry)
    db.session.commit()

    return jsonify({'message': f'File {filename} from bin {bin_id} has been deleted.'}), 200


@bp.route('/bin/<bin_id>', methods=['DELETE'])

@jwt_required()
def delete_bin(bin_id):
    # Step 1: Query bin
    user = get_jwt_identity()
    bin_entry = Bin.query.filter_by(bin_id=bin_id).first()
    print("user_id from token:", user)
    print("user_id from bin:", bin_entry.user_id)

    if not bin_entry:
        return jsonify({'error': 'Bin not found'}), 404
    
    if int(bin_entry.user_id )!= int(user):
        return jsonify({"error": "Unauthorized"}), 403

    # Step 2: Delete files from disk
    bin_dir = os.path.join(UPLOAD_DIR, bin_id)
    if os.path.exists(bin_dir):
        shutil.rmtree(bin_dir)

    # Step 3: Delete file records
    File.query.filter_by(bin_id=bin_id).delete()

    # Step 4: Delete bin record
    db.session.delete(bin_entry)
    db.session.commit()

    return jsonify({'message': f'Bin {bin_id} and all associated files have been deleted.'}), 200