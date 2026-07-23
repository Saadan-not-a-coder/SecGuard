#!/usr/bin/env python3
"""
Password Strength Module - Analyzes password security
"""

import re
import math
import string

COMMON_PASSWORDS = {
    'password', '123456', '123456789', '12345', '12345678', 'qwerty', 'abc123',
    'admin', 'letmein', 'welcome', 'monkey', 'password1', '1234', '1234567',
    'sunshine', 'iloveyou', 'princess', 'dragon', 'baseball', 'superman',
    'qwertyuiop', '111111', '123123', 'football', 'master', 'hello',
    'freedom', 'whatever', 'computer', 'internet', 'orange', 'banana',
    'microsoft', 'google', 'apple', 'windows', 'linux', 'ubuntu'
}

def analyze_password(password):
    """
    Analyze password strength and provide feedback
    
    Args:
        password: Password to analyze
    
    Returns:
        dict: Analysis results with score and suggestions
    """
    
    results = {
        'password': '*' * len(password),
        'length': len(password),
        'score': 0,
        'strength': 'Weak',
        'crack_time': '',
        'issues': [],
        'suggestions': []
    }
    
    # Check length
    if len(password) < 8:
        results['issues'].append('Password is too short (minimum 8 characters)')
        results['score'] += 5
    elif len(password) < 12:
        results['score'] += 15
        results['suggestions'].append('Consider using 12+ characters for better security')
    else:
        results['score'] += 25
    
    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        results['score'] += 10
    else:
        results['issues'].append('No uppercase letters found')
        results['suggestions'].append('Add uppercase letters (A-Z)')
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        results['score'] += 10
    else:
        results['issues'].append('No lowercase letters found')
        results['suggestions'].append('Add lowercase letters (a-z)')
    
    # Check for numbers
    if re.search(r'\d', password):
        results['score'] += 10
    else:
        results['issues'].append('No numbers found')
        results['suggestions'].append('Add numbers (0-9)')
    
    # Check for special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        results['score'] += 15
    else:
        results['issues'].append('No special characters found')
        results['suggestions'].append('Add special characters (!@#$%^&*)')
    
    # Check for common patterns
    if password.lower() in COMMON_PASSWORDS:
        results['issues'].append('Common password detected')
        results['score'] = 10
    else:
        results['score'] += 15
    
    # Check for keyboard patterns
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'password', '123456']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            results['issues'].append(f'Contains keyboard pattern: {pattern}')
            results['score'] = max(10, results['score'] - 10)
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        results['issues'].append('Contains repeated characters')
        results['score'] = max(10, results['score'] - 10)
    
    # Check for sequential characters
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
        results['issues'].append('Contains sequential characters')
        results['score'] = max(10, results['score'] - 10)
    
    # Calculate strength
    if results['score'] >= 80:
        results['strength'] = 'Very Strong 💪'
        results['crack_time'] = 'Centuries'
    elif results['score'] >= 60:
        results['strength'] = 'Strong 🔒'
        results['crack_time'] = 'Years'
    elif results['score'] >= 40:
        results['strength'] = 'Medium 🔓'
        results['crack_time'] = 'Days'
    elif results['score'] >= 20:
        results['strength'] = 'Weak ⚠️'
        results['crack_time'] = 'Hours'
    else:
        results['strength'] = 'Very Weak 🚨'
        results['crack_time'] = 'Seconds'
    
    # Estimate entropy
    char_set = 0
    if re.search(r'[a-z]', password):
        char_set += 26
    if re.search(r'[A-Z]', password):
        char_set += 26
    if re.search(r'\d', password):
        char_set += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        char_set += 33
    
    if char_set > 0:
        entropy = len(password) * math.log2(char_set)
        results['entropy'] = round(entropy, 1)
    
    # Final score cap
    results['score'] = min(100, results['score'])
    
    return results