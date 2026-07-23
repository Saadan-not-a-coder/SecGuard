#!/usr/bin/env python3
"""
Log Analysis Module - Detects security threats in system logs
"""

import re
import os
from collections import Counter
from datetime import datetime

# Comprehensive pattern definitions for different log types
PATTERNS = {
    'ssh': {
        'failed': r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)',
        'accepted': r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)',
        'invalid_user': r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
        'authentication': r'Authentication failure for (\S+) from (\d+\.\d+\.\d+\.\d+)',
        'disconnect': r'Disconnecting.*from (\d+\.\d+\.\d+\.\d+)',
        'connection_closed': r'Connection closed by (\d+\.\d+\.\d+\.\d+)',
        'rejected': r'Rejected.*from (\d+\.\d+\.\d+\.\d+)',
        'breakin': r'(Possible|Break-in).*from (\d+\.\d+\.\d+\.\d+)',
        'attack_patterns': [
            (r'[Ff]ailed password', 'SSH Brute Force Attempt'),
            (r'[Ii]nvalid user', 'SSH User Enumeration'),
            (r'[Aa]uthentication failure', 'SSH Authentication Failure'),
            (r'[Dd]isconnecting', 'SSH Disconnect'),
            (r'[Cc]onnection closed', 'SSH Connection Closed'),
            (r'[Rr]ejected', 'SSH Connection Rejected'),
            (r'[Bb]reak-in', 'SSH Break-in Attempt'),
            (r'[Aa]ccount locked', 'SSH Account Locked'),
            (r'[Pp]ossible', 'SSH Suspicious Activity'),
        ]
    },
    'http': {
        'attack_patterns': [
            (r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).*FROM', 'SQL Injection Attempt'),
            (r'(?i)<script.*>.*</script>', 'XSS Attack Attempt'),
            (r'(?i)\.\./\.\./', 'Directory Traversal'),
            (r'(?i)wp-admin|wp-login|wp-includes', 'WordPress Admin Attack'),
            (r'(?i)phpMyAdmin|mysql|phpinfo|php\.ini', 'Sensitive Path Access'),
            (r'(?i)\.env|\.git|\.aws|\.ssh|\.htaccess', 'Sensitive File Access'),
            (r'(?i)/admin/|/login/|/signin/', 'Admin Panel Access'),
            (r'(?i)\.(pdf|doc|docx|xls|xlsx|zip|rar|7z|sql|bak|backup)', 'Sensitive File Download'),
            (r'(?i)\.\.|%2e%2e|%252e%252e', 'Path Traversal Attempt'),
            (r'(?i)union.*select', 'SQL Injection Attempt'),
            (r'(?i)exec.*\(', 'Command Injection Attempt'),
            (r'(?i)system\s*\(', 'System Command Attempt'),
        ]
    },
    'auth': {
        'attack_patterns': [
            (r'[Aa]uthentication failure', 'Authentication Failure'),
            (r'[Pp]am_unix.*authentication failure', 'PAM Authentication Failure'),
            (r'[Ff]ailed login', 'Login Failure'),
            (r'[Ii]llegal user', 'Illegal User Attempt'),
            (r'[Bb]ad password', 'Bad Password Attempt'),
            (r'[Ll]ogin failed', 'Login Failure'),
        ]
    },
    'syslog': {
        'attack_patterns': [
            (r'[Kk]ernel:.*\[UFW BLOCK\]', 'Firewall Block'),
            (r'[Kk]ernel:.*\[UFW ALLOW\]', 'Firewall Allow'),
            (r'[Ff]ailed.*login', 'Login Failure'),
            (r'[Ss]udo.*[Ff]ailed', 'Sudo Failure'),
            (r'[Ee]rror.*[Aa]uthentication', 'Authentication Error'),
            (r'[Ss]ecurity.*[Aa]lert', 'Security Alert'),
        ]
    }
}

def analyze_logs(log_file, log_type='ssh'):
    """
    Analyze a log file for security threats
    
    Args:
        log_file: Path to log file
        log_type: Type of log ('ssh', 'http', 'auth', 'syslog')
    
    Returns:
        dict: Analysis results with findings and risk assessment
    """
    
    # Check if file exists
    if not os.path.exists(log_file):
        return {
            'error': f'File not found: {log_file}',
            'filename': log_file,
            'total_lines': 0,
            'suspicious_count': 0,
            'risk_level': '❌ Error - File Not Found'
        }
    
    # Initialize results
    results = {
        'filename': log_file,
        'total_lines': 0,
        'suspicious_count': 0,
        'attack_types': Counter(),
        'attackers': Counter(),
        'top_attackers': {},
        'suspicious_events': [],
        'threat_score': 0,
        'risk_level': '✅ Low (No suspicious activity detected)'
    }
    
    # Get patterns for this log type
    log_patterns = PATTERNS.get(log_type, PATTERNS['ssh'])
    attack_patterns = log_patterns.get('attack_patterns', [])
    
    # IP regex pattern
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    
    try:
        # Read file with proper encoding handling
        with open(log_file, 'rb') as f:
            raw_content = f.read()
        
        # Handle BOM (Byte Order Mark) if present
        if raw_content.startswith(b'\xef\xbb\xbf'):
            content = raw_content[3:].decode('utf-8', errors='ignore')
        else:
            try:
                content = raw_content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                content = raw_content.decode('latin-1', errors='ignore')
        
        # Split into lines
        lines = content.splitlines()
        
        # Process each line
        for line_num, line in enumerate(lines, 1):
            results['total_lines'] += 1
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
            
            # Check against attack patterns
            for pattern, attack_type in attack_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    results['suspicious_count'] += 1
                    results['attack_types'][attack_type] += 1
                    
                    # Extract IP from line
                    ips = ip_pattern.findall(line_stripped)
                    ip = ips[0] if ips else 'unknown'
                    results['attackers'][ip] += 1
                    
                    results['suspicious_events'].append({
                        'line': line_num,
                        'type': attack_type,
                        'ip': ip,
                        'content': line_stripped[:200]
                    })
                    break  # Only count once per line
            
            # SSH specific additional checks
            if log_type == 'ssh':
                # Check for failed password attempts
                failed_match = re.search(PATTERNS['ssh']['failed'], line_stripped)
                if failed_match:
                    # Check if already counted for this line
                    already_counted = False
                    for event in results['suspicious_events']:
                        if event['line'] == line_num:
                            already_counted = True
                            break
                    if not already_counted:
                        results['suspicious_count'] += 1
                        results['attack_types']['SSH Brute Force'] += 1
                        user, ip = failed_match.groups()
                        results['attackers'][ip] += 1
                        results['suspicious_events'].append({
                            'line': line_num,
                            'type': 'SSH Brute Force',
                            'ip': ip,
                            'content': line_stripped[:200]
                        })
                
                # Check for invalid user
                invalid_match = re.search(PATTERNS['ssh']['invalid_user'], line_stripped)
                if invalid_match:
                    already_counted = False
                    for event in results['suspicious_events']:
                        if event['line'] == line_num:
                            already_counted = True
                            break
                    if not already_counted:
                        results['suspicious_count'] += 1
                        results['attack_types']['SSH User Enumeration'] += 1
                        user, ip = invalid_match.groups()
                        results['attackers'][ip] += 1
                        results['suspicious_events'].append({
                            'line': line_num,
                            'type': 'SSH User Enumeration',
                            'ip': ip,
                            'content': line_stripped[:200]
                        })
                
                # Check for authentication failure
                auth_match = re.search(PATTERNS['ssh']['authentication'], line_stripped)
                if auth_match:
                    already_counted = False
                    for event in results['suspicious_events']:
                        if event['line'] == line_num:
                            already_counted = True
                            break
                    if not already_counted:
                        results['suspicious_count'] += 1
                        results['attack_types']['SSH Authentication Failure'] += 1
                        user, ip = auth_match.groups()
                        results['attackers'][ip] += 1
                        results['suspicious_events'].append({
                            'line': line_num,
                            'type': 'SSH Authentication Failure',
                            'ip': ip,
                            'content': line_stripped[:200]
                        })
            
            # HTTP specific additional checks
            if log_type == 'http':
                # Check for WordPress admin access attempts
                if re.search(r'(?i)wp-admin|wp-login', line_stripped):
                    already_counted = False
                    for event in results['suspicious_events']:
                        if event['line'] == line_num:
                            already_counted = True
                            break
                    if not already_counted:
                        results['suspicious_count'] += 1
                        results['attack_types']['WordPress Attack'] += 1
                        ips = ip_pattern.findall(line_stripped)
                        ip = ips[0] if ips else 'unknown'
                        results['attackers'][ip] += 1
                        results['suspicious_events'].append({
                            'line': line_num,
                            'type': 'WordPress Attack',
                            'ip': ip,
                            'content': line_stripped[:200]
                        })
                
                # Check for directory traversal attempts
                if re.search(r'(?i)\.\./\.\./|\.\.%2f|%2e%2e', line_stripped):
                    already_counted = False
                    for event in results['suspicious_events']:
                        if event['line'] == line_num:
                            already_counted = True
                            break
                    if not already_counted:
                        results['suspicious_count'] += 1
                        results['attack_types']['Directory Traversal'] += 1
                        ips = ip_pattern.findall(line_stripped)
                        ip = ips[0] if ips else 'unknown'
                        results['attackers'][ip] += 1
                        results['suspicious_events'].append({
                            'line': line_num,
                            'type': 'Directory Traversal',
                            'ip': ip,
                            'content': line_stripped[:200]
                        })
                
                # Check for SQL injection attempts
                if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*FROM', line_stripped):
                    already_counted = False
                    for event in results['suspicious_events']:
                        if event['line'] == line_num:
                            already_counted = True
                            break
                    if not already_counted:
                        results['suspicious_count'] += 1
                        results['attack_types']['SQL Injection'] += 1
                        ips = ip_pattern.findall(line_stripped)
                        ip = ips[0] if ips else 'unknown'
                        results['attackers'][ip] += 1
                        results['suspicious_events'].append({
                            'line': line_num,
                            'type': 'SQL Injection',
                            'ip': ip,
                            'content': line_stripped[:200]
                        })
    
    except Exception as e:
        results['error'] = f'Error reading file: {str(e)}'
        return results
    
    # Get top attackers
    results['top_attackers'] = dict(results['attackers'].most_common(10))
    
    # Generate threat score and risk level
    suspicious = results['suspicious_count']
    total = results['total_lines']
    
    if suspicious == 0:
        results['threat_score'] = 0
        results['risk_level'] = '✅ Low (No suspicious activity detected)'
    elif suspicious < 3:
        results['threat_score'] = 15
        results['risk_level'] = '✅ Low (Minimal suspicious activity)'
    elif suspicious < 8:
        results['threat_score'] = 35
        results['risk_level'] = '⚠️ Low-Medium (Some suspicious activity)'
    elif suspicious < 15:
        results['threat_score'] = 55
        results['risk_level'] = '⚠️ Medium (Moderate suspicious activity)'
    elif suspicious < 30:
        results['threat_score'] = 75
        results['risk_level'] = '🚨 High (Significant suspicious activity)'
    else:
        results['threat_score'] = 95
        results['risk_level'] = '🚨 Critical (Massive suspicious activity detected!)'
    
    return results