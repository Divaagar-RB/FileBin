from cachetools import cached
from typing import Optional, List, Dict
from backend.models import Bin, File
from backend.cache_manager import cache_manager

@cached(cache_manager.bin_cache)
def get_bin_by_id(bin_id: str) -> Optional[Bin]:
    """Get bin metadata with caching"""
    print(f"🔍 Fetching bin {bin_id} from database")
    return Bin.query.filter_by(bin_id=bin_id).first()

@cached(cache_manager.file_list_cache)
def get_bin_files_cached(bin_id: str) -> List[Dict]:
    """Get bin files with caching"""
    print(f"🔍 Fetching files for bin {bin_id} from database")
    bin_entry = Bin.query.filter_by(bin_id=bin_id).first()
    
    if not bin_entry:
        return []
    
    files_data = []
    for f in bin_entry.files:
        files_data.append({
            'filename': f.filename,
            'download_url': f'/bin/{bin_id}/download/{f.filename}',
            'delete_url': f'/bin/{bin_id}/file/{f.filename}',
            'filepath': f.filepath,
            'id': f.id
        })
    
    return files_data

@cached(cache_manager.user_bins_cache)
def get_user_bins_cached(user_id: str) -> List[Dict]:
    """Get user's bins with caching"""
    print(f"🔍 Fetching bins for user {user_id} from database")
    bins = Bin.query.filter_by(user_id=user_id).all()
    
    bins_data = []
    for bin_entry in bins:
        file_count = len(bin_entry.files) if bin_entry.files else 0
        bins_data.append({
            'bin_id': bin_entry.bin_id,
            'created_at': bin_entry.created_at.isoformat() if hasattr(bin_entry, 'created_at') else None,
            'file_count': file_count
        })
    
    return bins_data

def get_file_by_bin_and_name_cached(bin_id: str, filename: str) -> Optional[File]:
    """Get specific file with caching"""
    cache_key = f"file_{bin_id}_{filename}"
    
    if cache_key in cache_manager.file_exists_cache:
        print(f"💾 Cache HIT for file {filename} in bin {bin_id}")
        return cache_manager.file_exists_cache[cache_key]
    
    print(f"🔍 Fetching file {filename} from bin {bin_id} from database")
    file_entry = File.query.filter_by(bin_id=bin_id, filename=filename).first()
    cache_manager.file_exists_cache[cache_key] = file_entry
    
    return file_entry

@cached(cache_manager.auth_cache)
def verify_user_bin_access(user_id: str, bin_id: str) -> bool:
    """Verify user has access to bin with caching"""
    print(f"🔐 Verifying access: user {user_id} to bin {bin_id}")
    bin_entry = Bin.query.filter_by(bin_id=bin_id, user_id=user_id).first()
    return bin_entry is not None

# Cache invalidation helpers
def invalidate_file_cache(bin_id: str, filename: str = None):
    """Invalidate file-related caches"""
    if filename:
        # Remove specific file cache
        cache_key = f"file_{bin_id}_{filename}"
        cache_manager.file_exists_cache.pop(cache_key, None)
    
    # Always invalidate bin caches when files change
    cache_manager.invalidate_bin_cache(bin_id)

def invalidate_bin_and_user_cache(bin_id: str, user_id: str):
    """Invalidate both bin and user caches"""
    cache_manager.invalidate_bin_cache(bin_id)
    cache_manager.invalidate_user_cache(user_id)