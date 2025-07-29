import os
import uuid
import io
import zipfile
import shutil
from flask import send_file
from flask import Blueprint, request, jsonify, send_from_directory, current_app
from werkzeug.utils import secure_filename
from backend.models import Bin, File
from backend.extensions import db
from hashids import Hashids
from flask_jwt_extended import jwt_required, get_jwt_identity

# Import cached services
from backend.cached_services import (
    get_bin_by_id, 
    get_bin_files_cached, 
    get_user_bins_cached,
    get_file_by_bin_and_name_cached,
    verify_user_bin_access,
    invalidate_file_cache,
    invalidate_bin_and_user_cache
)
from backend.cache_manager import cache_manager

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
    new_bin = Bin(user_id=user_id, bin_id="temp")
    db.session.add(new_bin)
    db.session.flush()

    # Step 2: Obfuscate the ID
    obfuscated_id = hashids.encode(new_bin.id)
    new_bin.bin_id = obfuscated_id

    # Step 3: Save each file
    bin_dir = os.path.join(UPLOAD_DIR, obfuscated_id)
    os.makedirs(bin_dir, exist_ok=True)

    saved_files = []
    for file in uploaded_files:
        if file.filename == '':
            continue

        filename = secure_filename(file.filename)
        file_path = os.path.join(bin_dir, filename)
        file.save(file_path)

        new_file = File(
            bin_id=obfuscated_id,
            filename=filename,
            filepath=file_path
        )
        db.session.add(new_file)
        saved_files.append(filename)

    db.session.commit()
    
    # 🚀 CACHE: Invalidate user cache since they have a new bin
    cache_manager.invalidate_user_cache(user_id)
    
    print(f"✅ Created bin {obfuscated_id} with {len(saved_files)} files")

    return jsonify({
        'bin_id': obfuscated_id,
        'file_url': f'/bin/{obfuscated_id}',
        'user_id': new_bin.user_id,
        'files_uploaded': len(saved_files)
    }), 201

@bp.route('/bin/<bin_id>/upload', methods=['POST'])
@jwt_required()
def upload_to_existing_bin(bin_id):
    user_id = get_jwt_identity()
    
    # 🚀 CACHE: Use cached access verification
    if not verify_user_bin_access(user_id, bin_id):
        return jsonify({'error': 'Bin not found or unauthorized'}), 404

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
    
    # 🚀 CACHE: Invalidate caches
    cache_manager.invalidate_user_cache(user_id)
    invalidate_bin_and_user_cache(bin_id, user_id)

    return jsonify({
        'message': f'{len(saved_files)} file(s) added to bin {bin_id}',
        'files': saved_files
    }), 201

@bp.route('/bin/<bin_id>', methods=['GET'])
def get_bin_files(bin_id):
    # 🚀 CACHE: Use cached bin lookup
    bin_entry = get_bin_by_id(bin_id)
    if not bin_entry:
        return jsonify({'error': 'Bin not found'}), 404

    # 🚀 CACHE: Use cached file listing
    files = get_bin_files_cached(bin_id)

    return jsonify({
        'bin_id': bin_id,
        'user_id': bin_entry.user_id,
        'files': files,
        'file_count': len(files)
    })

@bp.route('/bin/<bin_id>/download/<filename>', methods=['GET'])
def download_file(bin_id, filename):
    # 🚀 CACHE: Check if file exists using cache
    file_entry = get_file_by_bin_and_name_cached(bin_id, filename)
    if not file_entry:
        return jsonify({'error': 'File not found'}), 404

    bin_path = os.path.join(UPLOAD_DIR, bin_id)

    try:
        return send_from_directory(
            directory=bin_path,
            path=filename,
            as_attachment=True
        )
    except FileNotFoundError:
        # File was deleted from disk but still in DB - invalidate cache
        invalidate_file_cache(bin_id, filename)
        return jsonify({'error': 'File not found on disk'}), 404

@bp.route('/bin/<bin_id>/download_all', methods=['GET'])
def download_all_files(bin_id):
    # 🚀 CACHE: Use cached bin lookup
    bin_entry = get_bin_by_id(bin_id)
    if not bin_entry:
        return jsonify({'error': 'Bin not found'}), 404

    bin_path = os.path.join(UPLOAD_DIR, bin_id)
    if not os.path.exists(bin_path):
        return jsonify({'error': 'Bin directory not found'}), 404

    # Create in-memory zip
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for filename in os.listdir(bin_path):
            file_path = os.path.join(bin_path, filename)
            zipf.write(file_path, arcname=filename)

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
    user_id = get_jwt_identity()
    
    # 🚀 CACHE: Use cached access verification
    if not verify_user_bin_access(user_id, bin_id):
        return jsonify({'error': 'Unauthorized or bin not found'}), 403

    # 🚀 CACHE: Use cached file lookup
    file_entry = get_file_by_bin_and_name_cached(bin_id, filename)
    if not file_entry:
        return jsonify({'error': 'File not found in this bin'}), 404

    # Delete file from disk
    if os.path.exists(file_entry.filepath):
        os.remove(file_entry.filepath)

    # Delete file record from DB
    db.session.delete(file_entry)
    db.session.commit()
    
    # 🚀 CACHE: Invalidate caches
    invalidate_file_cache(bin_id, filename)
    invalidate_bin_and_user_cache(bin_id, user_id)

    cache_manager.invalidate_user_cache(user_id)

    return jsonify({'message': f'File {filename} from bin {bin_id} has been deleted.'}), 200

# IMMEDIATE FIX: Replace your delete_bin endpoint with this version

@bp.route('/bin/<bin_id>', methods=['DELETE'])
@jwt_required()
def delete_bin(bin_id):
    user_id = get_jwt_identity()
    
    # Get bin entry directly from DB (bypass cache for verification)
    bin_entry = Bin.query.filter_by(bin_id=bin_id).first()
    if not bin_entry:
        return jsonify({'error': 'Bin not found'}), 404
    
    if int(bin_entry.user_id) != int(user_id):
        return jsonify({"error": "Unauthorized"}), 403

    print(f"🗑️ Starting deletion of bin {bin_id} for user {user_id}")

    # Delete files from disk
    bin_dir = os.path.join(UPLOAD_DIR, bin_id)
    if os.path.exists(bin_dir):
        shutil.rmtree(bin_dir)
        print(f"🗑️ Deleted directory: {bin_dir}")

    # Delete file records from DB
    files_deleted = File.query.filter_by(bin_id=bin_id).delete()
    print(f"🗑️ Deleted {files_deleted} file records from DB")

    # Delete bin record from DB
    db.session.delete(bin_entry)
    db.session.commit()
    print(f"🗑️ Deleted bin {bin_id} from DB")
    
    # AGGRESSIVE CACHE CLEARING - Clear everything related to this user
    try:
        # Clear user bins cache
        if hasattr(cache_manager, 'user_bins_cache') and user_id in cache_manager.user_bins_cache:
            del cache_manager.user_bins_cache[user_id]
            print(f"🧹 Cleared user_bins_cache for user {user_id}")
        
        # Clear bin cache
        if hasattr(cache_manager, 'bin_cache') and bin_id in cache_manager.bin_cache:
            del cache_manager.bin_cache[bin_id]
            print(f"🧹 Cleared bin_cache for bin {bin_id}")
        
        # Clear file list cache
        if hasattr(cache_manager, 'file_list_cache') and bin_id in cache_manager.file_list_cache:
            del cache_manager.file_list_cache[bin_id]
            print(f"🧹 Cleared file_list_cache for bin {bin_id}")
            
        # Clear auth cache if it exists
        if hasattr(cache_manager, 'auth_cache'):
            # Clear any auth cache entries that might reference this bin
            auth_keys_to_remove = []
            for key in cache_manager.auth_cache.keys():
                if bin_id in str(key):
                    auth_keys_to_remove.append(key)
            for key in auth_keys_to_remove:
                del cache_manager.auth_cache[key]
                print(f"🧹 Cleared auth_cache key: {key}")
        
        # Clear file exists cache if it exists
        if hasattr(cache_manager, 'file_exists_cache'):
            file_keys_to_remove = []
            for key in cache_manager.file_exists_cache.keys():
                if bin_id in str(key):
                    file_keys_to_remove.append(key)
            for key in file_keys_to_remove:
                del cache_manager.file_exists_cache[key]
                print(f"🧹 Cleared file_exists_cache key: {key}")
        
        # Call the invalidation functions as backup
        if 'invalidate_bin_and_user_cache' in globals():
            invalidate_bin_and_user_cache(bin_id, user_id)
            print(f"🧹 Called invalidate_bin_and_user_cache({bin_id}, {user_id})")
        
        if hasattr(cache_manager, 'invalidate_user_cache'):
            cache_manager.invalidate_user_cache(user_id)
            print(f"🧹 Called cache_manager.invalidate_user_cache({user_id})")
            
    except Exception as e:
        print(f"⚠️ Error during cache clearing: {e}")
        # Continue anyway - cache clearing failure shouldn't stop deletion

    print(f"✅ Successfully deleted bin {bin_id} and cleared all caches for user {user_id}")

    return jsonify({'message': f'Bin {bin_id} and all associated files have been deleted.'}), 200


# ALSO UPDATE: get_user_bins to always check DB for existence
@bp.route('/user/bins', methods=['GET'])
@jwt_required()
def get_user_bins():
    user_id = get_jwt_identity()
    
    print(f"📋 Fetching bins for user {user_id}")

    # Check if we should force refresh
    force_refresh = request.args.get('refresh', '').lower() == 'true'
    
    if force_refresh:
        print(f"🔄 Force refresh requested for user {user_id}")
        # Clear cache first
        if hasattr(cache_manager, 'user_bins_cache') and user_id in cache_manager.user_bins_cache:
            del cache_manager.user_bins_cache[user_id]
        cached_bins = None
    else:
        # Try cache first
        cached_bins = cache_manager.user_bins_cache.get(user_id) if hasattr(cache_manager, 'user_bins_cache') else None
    
    refreshed_bins = []

    # ALWAYS verify cache against DB to catch deleted bins
    if cached_bins and not force_refresh:
        print(f"📋 Found {len(cached_bins)} cached bins, verifying against DB...")
        valid_bins = []
        
        for cached_bin in cached_bins:
            # Check if bin still exists in DB
            bin_exists = Bin.query.filter_by(bin_id=cached_bin['bin_id']).first()
            if bin_exists:
                # Bin exists, check file count
                db_file_count = File.query.filter_by(bin_id=cached_bin['bin_id']).count()
                valid_bins.append({
                    'bin_id': cached_bin['bin_id'],
                    'file_count': db_file_count,
                    'created_at': bin_exists.created_at
                })
                print(f"✅ Bin {cached_bin['bin_id']} exists with {db_file_count} files")
            else:
                print(f"❌ Bin {cached_bin['bin_id']} no longer exists in DB - removing from cache")
        
        refreshed_bins = valid_bins
        
        # If we found invalid bins, update the cache
        if len(valid_bins) != len(cached_bins):
            cache_manager.user_bins_cache[user_id] = valid_bins
            print(f"🔄 Updated cache: {len(cached_bins)} -> {len(valid_bins)} bins")

    else:
        # No cache or force refresh → fetch fresh from DB
        print(f"📋 Fetching fresh data from DB for user {user_id}")
        user_bins = Bin.query.filter_by(user_id=user_id).all()
        
        for bin_entry in user_bins:
            file_count = File.query.filter_by(bin_id=bin_entry.bin_id).count()
            refreshed_bins.append({
                'bin_id': bin_entry.bin_id,
                'file_count': file_count,
                'created_at': bin_entry.created_at
            })
            print(f"📁 Found bin {bin_entry.bin_id} with {file_count} files")
        
        # Save to cache
        if hasattr(cache_manager, 'user_bins_cache'):
            cache_manager.user_bins_cache[user_id] = refreshed_bins

    print(f"✅ Returning {len(refreshed_bins)} bins for user {user_id}")

    return jsonify({
        'user_id': user_id,
        'bins': refreshed_bins,
        'total_bins': len(refreshed_bins)
    })


# DEBUG ENDPOINT: Add this to help debug cache issues
@bp.route('/debug/cache-status/<int:user_id>', methods=['GET'])
@jwt_required()
def debug_cache_status(user_id):
    """Debug endpoint to see cache contents"""
    current_user = get_jwt_identity()
    if int(current_user) != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    cache_status = {}
    
    # Check user bins cache
    if hasattr(cache_manager, 'user_bins_cache'):
        cached_bins = cache_manager.user_bins_cache.get(user_id)
        cache_status['user_bins_cache'] = {
            'exists': cached_bins is not None,
            'count': len(cached_bins) if cached_bins else 0,
            'bins': cached_bins
        }
    
    # Check DB reality
    db_bins = Bin.query.filter_by(user_id=user_id).all()
    cache_status['database_reality'] = {
        'count': len(db_bins),
        'bins': [{'bin_id': b.bin_id, 'created_at': str(b.created_at)} for b in db_bins]
    }
    
    return jsonify(cache_status)


# NUCLEAR OPTION: Clear all caches
@bp.route('/debug/nuclear-cache-clear', methods=['POST'])
@jwt_required()
def nuclear_cache_clear():
    """Clear ALL caches - use when everything is broken"""
    try:
        if hasattr(cache_manager, 'user_bins_cache'):
            cache_manager.user_bins_cache.clear()
        if hasattr(cache_manager, 'bin_cache'):
            cache_manager.bin_cache.clear()
        if hasattr(cache_manager, 'file_list_cache'):
            cache_manager.file_list_cache.clear()
        if hasattr(cache_manager, 'auth_cache'):
            cache_manager.auth_cache.clear()
        if hasattr(cache_manager, 'file_exists_cache'):
            cache_manager.file_exists_cache.clear()
        
        return jsonify({'message': 'All caches nuked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Alternative: Add a debug endpoint to force cache clear
@bp.route('/debug/clear-user-cache', methods=['POST'])
@jwt_required()
def clear_user_cache():
    user_id = get_jwt_identity()
    cache_manager.invalidate_user_cache(user_id)
    
    # Also clear any related caches
    user_bins = Bin.query.filter_by(user_id=user_id).all()
    for bin_entry in user_bins:
        cache_manager.bin_cache.pop(bin_entry.bin_id, None)
        cache_manager.file_list_cache.pop(bin_entry.bin_id, None)
    
    return jsonify({'message': f'Cache cleared for user {user_id}'})

@bp.route('/cache/stats', methods=['GET'])
@jwt_required()
def get_cache_stats():
    """Get cache statistics for monitoring"""
    return jsonify({
        'bin_cache': {
            'size': len(cache_manager.bin_cache),
            'max_size': cache_manager.bin_cache.maxsize,
        },
        'file_list_cache': {
            'size': len(cache_manager.file_list_cache),
            'max_size': cache_manager.file_list_cache.maxsize,
        },
        'user_bins_cache': {
            'size': len(cache_manager.user_bins_cache),
            'max_size': cache_manager.user_bins_cache.maxsize,
        },
        'auth_cache': {
            'size': len(cache_manager.auth_cache),
            'max_size': cache_manager.auth_cache.maxsize,
        }
    })

@bp.route('/cache/clear', methods=['POST'])
@jwt_required()
def clear_all_caches():
    """Clear all caches - admin function"""
    cache_manager.bin_cache.clear()
    cache_manager.file_list_cache.clear()
    cache_manager.user_bins_cache.clear()
    cache_manager.auth_cache.clear()
    cache_manager.file_exists_cache.clear()
    
    return jsonify({'message': 'All caches cleared successfully'})