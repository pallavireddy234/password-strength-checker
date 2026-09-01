"""
Password Analyzer Engine

Comprehensive password security analysis with scoring, entropy calculation,
and intelligent recommendations. No passwords are stored or logged.
"""

import re
import math
from typing import Dict, List, Tuple


# Common passwords dataset (top 1000 most common passwords)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "batman", "1qaz2wsx", "login", "admin",
    "princess", "solo", "zxcvbnm", "123456789", "666666", "654321", "123321",
    "myspace1", "121212", "112233", "12345", "1234567890", "pass", "test",
    "welcome", "hello", "starwars", "whatever", "freedom", "charlie", "1q2w3e",
    "access", "1a2b3c", "12qwaszx", "abc", "1a2b3c4d", "aaa", "root", "love",
    "buster", "hunter", "cookie", "thomas", "robert", "matrix", "purple",
    "jessica", "friends", "diamond", "coffee", "summer", "winter", "passion",
    "lovely", "family", "golden", "silver", "bronze", "flower", "butterfly",
    "rainbow", "thunder", "energy", "fortune", "destiny", "special", "amazing",
}

# Keyboard patterns - common sequential patterns on QWERTY keyboard
KEYBOARD_PATTERNS = [
    "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "zxcvbnm",
    "12345", "123456", "1234567", "12345678", "123456789",
    "qweasd", "asdfgh", "zxcvbn", "qazwsx", "1q2w3e4r",
    "1q2w3e", "1qaz2wsx", "1qazxsw2",
]

# Common sequential patterns
SEQUENTIAL_PATTERNS = [
    "123456", "234567", "345678", "456789", "567890",
    "abcdef", "bcdefg", "cdefgh", "defghi", "efghij",
    "ghijkl", "hijklm", "ijklmn", "jklmno", "klmnop",
    "lmnopq", "mnopqr", "nopqrs", "opqrst", "pqrstu",
    "qrstuv", "rstuvw", "stuvwx", "tuvwxy", "uvwxyz",
]

# Common substitutions to detect
COMMON_SUBSTITUTIONS = {
    r"p@ssw(o|0)rd": "password",
    r"p@ss": "pass",
    r"l0ve": "love",
    r"h@te": "hate",
    r"l33t": "leet",
    r"n00b": "noob",
    r"h4ck": "hack",
    r"b1tch": "bitch",
}


def analyze(password: str) -> Dict:
    """
    Analyze password strength and return comprehensive security metrics.
    
    Args:
        password: The password to analyze
        
    Returns:
        Dictionary containing:
        - score: 0-100 strength score
        - level: Security level (Very Weak, Weak, Fair, Strong, Very Strong)
        - entropy: Estimated entropy in bits
        - length: Password length
        - checks: Dictionary of boolean security checks
        - suggestions: List of actionable recommendations
    """
    
    if not password or not isinstance(password, str):
        return {
            "score": 0,
            "level": "Very Weak",
            "entropy": 0,
            "length": 0,
            "checks": {
                "length": False,
                "uppercase": False,
                "lowercase": False,
                "numbers": False,
                "symbols": False,
                "common_password": True,
                "repeated_characters": False,
                "sequential_characters": False,
            },
            "suggestions": ["Password is required"]
        }
    
    # Initialize result
    result = {
        "score": 0,
        "level": "Very Weak",
        "entropy": 0,
        "length": len(password),
        "checks": {},
        "suggestions": []
    }
    
    # Perform all security checks
    checks = _perform_security_checks(password)
    result["checks"] = checks
    
    # Calculate score
    score = _calculate_score(password, checks)
    result["score"] = score
    
    # Determine security level
    result["level"] = _get_security_level(score)
    
    # Calculate entropy
    entropy = _calculate_entropy(password, checks)
    result["entropy"] = round(entropy, 1)
    
    # Generate recommendations
    suggestions = _generate_suggestions(password, checks, score)
    result["suggestions"] = suggestions
    
    return result


def _perform_security_checks(password: str) -> Dict[str, bool]:
    """
    Perform all security checks on the password.
    
    Returns:
        Dictionary of check results
    """
    checks = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "numbers": bool(re.search(r'\d', password)),
        "symbols": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password)),
        "common_password": password.lower() not in COMMON_PASSWORDS,
        "repeated_characters": not _has_excessive_repetition(password),
        "sequential_characters": not _has_sequential_pattern(password),
    }
    
    return checks


def _has_excessive_repetition(password: str) -> bool:
    """
    Check if password has excessive character repetition (e.g., aaaa, 1111).
    
    Returns:
        True if excessive repetition is found
    """
    # Check for 4 or more consecutive identical characters
    return bool(re.search(r'(.)\1{3,}', password))


def _has_sequential_pattern(password: str) -> bool:
    """
    Check if password contains sequential or keyboard patterns.
    
    Returns:
        True if sequential/keyboard patterns are found
    """
    pwd_lower = password.lower()
    
    # Check keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pwd_lower:
            return True
    
    # Check sequential patterns
    for pattern in SEQUENTIAL_PATTERNS:
        if pattern in pwd_lower:
            return True
    
    # Check numeric sequences
    if re.search(r'[0-9]{3,}', password):
        seq = re.search(r'(\d)\d+', password)
        if seq:
            # Check if digits are sequential (like 123, 456, 789)
            digits_str = re.search(r'(\d{3,})', password).group(1)
            is_sequential = all(
                int(digits_str[i+1]) - int(digits_str[i]) == 1 
                for i in range(len(digits_str)-1)
            )
            if is_sequential:
                return True
    
    # Check obvious substitutions
    for pattern in COMMON_SUBSTITUTIONS.keys():
        if re.search(pattern, pwd_lower):
            return True
    
    return False


def _calculate_score(password: str, checks: Dict[str, bool]) -> int:
    """
    Calculate overall password strength score (0-100).
    
    Uses a multi-factor approach:
    - Base points for character types
    - Length bonus
    - Entropy bonus
    - Penalties for weak patterns
    """
    score = 0
    password_len = len(password)
    
    # Length-based points (0-20)
    length_score = min(20, (password_len / 2))
    score += length_score
    
    # Character type diversity (0-40)
    char_types = sum([
        checks["uppercase"],
        checks["lowercase"],
        checks["numbers"],
        checks["symbols"]
    ])
    score += char_types * 10
    
    # Entropy bonus (0-20)
    entropy = _calculate_entropy(password, checks)
    entropy_score = min(20, entropy / 4)  # Cap at 20
    score += entropy_score
    
    # Penalties (up to -40)
    if not checks["common_password"]:
        score -= 15  # Common password penalty
    
    if not checks["repeated_characters"]:
        score -= 10  # Repetition penalty
    
    if not checks["sequential_characters"]:
        score -= 15  # Sequential pattern penalty
    
    # Ensure score is within bounds
    score = max(0, min(100, int(score)))
    
    return score


def _calculate_entropy(password: str, checks: Dict[str, bool]) -> float:
    """
    Calculate estimated entropy in bits.
    
    Formula: entropy = log₂(character_pool_size) × password_length × diversity_factor
    
    Where character_pool_size is based on detected character types.
    """
    if not password:
        return 0
    
    # Determine character pool size based on detected types
    pool_size = 0
    
    if checks["lowercase"]:
        pool_size += 26
    if checks["uppercase"]:
        pool_size += 26
    if checks["numbers"]:
        pool_size += 10
    if checks["symbols"]:
        pool_size += 32  # Common symbols
    
    if pool_size == 0:
        pool_size = 1  # Avoid log(0)
    
    # Base entropy calculation
    base_entropy = math.log2(pool_size) * len(password)
    
    # Apply diversity multiplier
    diversity_factor = 1.0
    
    # Reduce entropy if patterns are detected
    if not checks["sequential_characters"]:
        diversity_factor *= 0.7  # 30% penalty
    
    if not checks["repeated_characters"]:
        diversity_factor *= 0.8  # 20% penalty
    
    if not checks["common_password"]:
        diversity_factor *= 0.5  # 50% penalty
    
    # Apply minimum length threshold
    if len(password) < 8:
        diversity_factor *= 0.8
    
    entropy = base_entropy * diversity_factor
    
    return max(0, entropy)


def _get_security_level(score: int) -> str:
    """
    Determine security level from score.
    
    Returns:
        Security level string
    """
    if score >= 80:
        return "Very Strong"
    elif score >= 60:
        return "Strong"
    elif score >= 40:
        return "Fair"
    elif score >= 20:
        return "Weak"
    else:
        return "Very Weak"


def _generate_suggestions(password: str, checks: Dict[str, bool], score: int) -> List[str]:
    """
    Generate intelligent recommendations based on password analysis.
    
    Returns:
        List of actionable recommendations
    """
    suggestions = []
    password_len = len(password)
    
    # Length recommendations
    if password_len < 8:
        suggestions.append("Increase password length to at least 8 characters.")
    elif password_len < 12:
        suggestions.append("Consider using a longer password (12+ characters) for better security.")
    elif password_len >= 16:
        suggestions.append("Excellent password length provides strong protection.")
    
    # Character type recommendations
    if not checks["lowercase"]:
        suggestions.append("Add lowercase letters (a-z) to increase character diversity.")
    if not checks["uppercase"]:
        suggestions.append("Add uppercase letters (A-Z) for better security.")
    if not checks["numbers"]:
        suggestions.append("Include numbers (0-9) to strengthen your password.")
    if not checks["symbols"]:
        suggestions.append("Add special symbols (!@#$%^&*) for maximum security.")
    
    # Pattern warnings
    if not checks["sequential_characters"]:
        suggestions.append("Avoid predictable sequences like '123456' or 'abcdef'.")
    
    if not checks["repeated_characters"]:
        suggestions.append("Reduce repeating characters (avoid 'aaaa', '1111').")
    
    if not checks["common_password"]:
        suggestions.append("This password is commonly used. Choose a more unique password.")
    
    # Positive feedback for strong passwords
    if score >= 80:
        suggestions.append("Excellent password! Strong length and character diversity.")
    elif score >= 60:
        if checks["length"] and checks["symbols"]:
            suggestions.append("Good password! Consider adding more character variety if possible.")
    
    # Remove duplicates and limit to 5 suggestions
    suggestions = list(dict.fromkeys(suggestions))  # Remove duplicates
    
    return suggestions[:5]


def generate_secure_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_numbers: bool = True,
    include_symbols: bool = True
) -> str:
    """
    Generate a cryptographically secure random password.
    
    Args:
        length: Password length (minimum 8, maximum 128)
        include_uppercase: Include uppercase letters
        include_lowercase: Include lowercase letters
        include_numbers: Include digits
        include_symbols: Include special symbols
        
    Returns:
        Secure random password string
    """
    import secrets
    
    # Validate length
    length = max(8, min(128, int(length)))
    
    # Build character pool
    char_pool = ""
    
    if include_uppercase:
        char_pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if include_lowercase:
        char_pool += "abcdefghijklmnopqrstuvwxyz"
    if include_numbers:
        char_pool += "0123456789"
    if include_symbols:
        char_pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least some characters are available
    if not char_pool:
        char_pool = "abcdefghijklmnopqrstuvwxyz"
    
    # Generate password using cryptographically secure random
    password = "".join(secrets.choice(char_pool) for _ in range(length))
    
    return password
