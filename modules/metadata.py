#!/usr/bin/env python3
"""
File Metadata Module - Extracts and analyzes file metadata
"""

import os
import hashlib
import datetime
import struct

def calculate_hash(filepath):
    """Calculate MD5 and SHA256 hashes of a file"""
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
        return hash_md5.hexdigest(), hash_sha256.hexdigest()
    except Exception:
        return None, None

def extract_exif(filepath):
    """Extract basic EXIF data from images (simplified)"""
    exif_data = {}
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        # Check for JPEG signature
        if data.startswith(b'\xff\xd8'):
            # Look for EXIF header
            exif_pos = data.find(b'Exif\x00\x00')
            if exif_pos != -1:
                exif_data['exif_present'] = True
                
                # Try to extract some basic info
                # Make/Model - look for ASCII strings
                try:
                    # Look for common EXIF tags
                    tags = {
                        b'Make': 'Make',
                        b'Model': 'Model',
                        b'DateTime': 'DateTime',
                        b'Copyright': 'Copyright'
                    }
                    
                    for tag_name, tag_value in tags.items():
                        pos = data.find(tag_name)
                        if pos != -1:
                            # Try to get the value
                            start = pos + len(tag_name) + 1
                            end = data.find(b'\x00', start)
                            if end != -1 and end - start < 100:
                                value = data[start:end].decode('utf-8', errors='ignore')
                                if value:
                                    exif_data[tag_value] = value
                except:
                    pass
                
        elif data.startswith(b'\x89PNG'):
            # PNG file - extract text chunks
            exif_data['type'] = 'PNG'
            pos = 8
            while pos < len(data) - 12:
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                if chunk_type == b'IHDR':
                    width, height = struct.unpack('>II', data[pos+8:pos+16])
                    exif_data['width'] = width
                    exif_data['height'] = height
                elif chunk_type == b'tEXt':
                    text_data = data[pos+8:pos+8+length]
                    try:
                        text = text_data.decode('utf-8', errors='ignore')
                        if '\x00' in text:
                            key, val = text.split('\x00', 1)
                            exif_data[key] = val
                    except:
                        pass
                pos += 12 + length
                
    except Exception:
        pass
    
    return exif_data

def extract_metadata(filepath):
    """
    Extract metadata from a file
    
    Args:
        filepath: Path to file
    
    Returns:
        dict: Extracted metadata
    """
    
    if not os.path.exists(filepath):
        return {'error': f'File not found: {filepath}'}
    
    results = {
        'filename': os.path.basename(filepath),
        'path': filepath,
        'size': '{} bytes'.format(os.path.getsize(filepath)),
        'size_bytes': os.path.getsize(filepath),
        'created': datetime.datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
        'modified': datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat(),
        'accessed': datetime.datetime.fromtimestamp(os.path.getatime(filepath)).isoformat(),
        'extension': os.path.splitext(filepath)[1],
        'readable': os.access(filepath, os.R_OK)
    }
    
    # Calculate hashes
    md5, sha256 = calculate_hash(filepath)
    results['md5'] = md5 if md5 else 'N/A'
    results['sha256'] = sha256 if sha256 else 'N/A'
    
    # Detect file type
    try:
        import magic
        results['file_type'] = magic.from_file(filepath)
    except ImportError:
        # Use extension as fallback
        ext = results['extension'].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            results['file_type'] = f'Image file ({ext})'
        elif ext in ['.pdf']:
            results['file_type'] = 'PDF Document'
        elif ext in ['.doc', '.docx']:
            results['file_type'] = 'Word Document'
        elif ext in ['.xls', '.xlsx']:
            results['file_type'] = 'Excel Spreadsheet'
        elif ext in ['.zip', '.tar', '.gz']:
            results['file_type'] = 'Archive file'
        else:
            results['file_type'] = 'Unknown'
    
    # Extract EXIF for images
    exif = extract_exif(filepath)
    if exif:
        results['exif_data'] = exif
    
    # Check for suspicious indicators
    results['indicators'] = []
    if results['size_bytes'] > 10 * 1024 * 1024:  # 10MB
        results['indicators'].append('Large file size')
    if results['extension'] in ['.exe', '.dll', '.bin', '.scr']:
        results['indicators'].append('Executable file')
    if 'exe' in results.get('file_type', '').lower():
        results['indicators'].append('Executable detected')
    
    # Risk level
    if results['indicators']:
        results['risk_level'] = '⚠️ Check'
    else:
        results['risk_level'] = '✅ Clean'
    
    return results