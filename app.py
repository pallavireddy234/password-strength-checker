"""
Password Strength Checker - Flask Application

A modern, full-stack password security analysis web application.
Features real-time analysis, entropy calculation, and intelligent recommendations.

Security Notes:
- Passwords are NOT stored
- Passwords are NOT logged
- Passwords are NOT sent to external services
- Passwords are analyzed in-session only
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from backend.password_analyzer import analyze, generate_secure_password


# Initialize Flask application
app = Flask(__name__)


@app.route('/')
def index():
    """Serve the main HTML interface."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    API endpoint for password analysis.
    
    Expects JSON POST request with 'password' field.
    Returns detailed security metrics and recommendations.
    """
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Validate request
        if not data:
            return jsonify({
                "error": "No JSON data provided"
            }), 400
        
        # Extract password
        password = data.get('password')
        
        # Validate password exists
        if password is None:
            return jsonify({
                "error": "Password field is required"
            }), 400
        
        # Validate password is string
        if not isinstance(password, str):
            return jsonify({
                "error": "Password must be a string"
            }), 400
        
        # Analyze password
        result = analyze(password)
        
        # Return result
        return jsonify(result), 200
        
    except json.JSONDecodeError:
        return jsonify({
            "error": "Invalid JSON format"
        }), 400
    except Exception as e:
        # Never expose internal error details
        return jsonify({
            "error": "Unable to analyze password. Please try again."
        }), 500


@app.route('/api/generate', methods=['POST'])
def api_generate():
    """
    API endpoint for secure password generation.
    
    Expects JSON POST request with optional generation parameters.
    Returns a cryptographically secure random password.
    """
    try:
        # Get JSON data from request
        data = request.get_json() or {}
        
        # Extract parameters with defaults
        length = data.get('length', 16)
        include_uppercase = data.get('include_uppercase', True)
        include_lowercase = data.get('include_lowercase', True)
        include_numbers = data.get('include_numbers', True)
        include_symbols = data.get('include_symbols', True)
        
        # Validate length
        try:
            length = int(length)
        except (ValueError, TypeError):
            return jsonify({
                "error": "Length must be a number"
            }), 400
        
        if length < 8 or length > 128:
            return jsonify({
                "error": "Length must be between 8 and 128"
            }), 400
        
        # Validate boolean flags
        try:
            include_uppercase = bool(include_uppercase)
            include_lowercase = bool(include_lowercase)
            include_numbers = bool(include_numbers)
            include_symbols = bool(include_symbols)
        except (ValueError, TypeError):
            return jsonify({
                "error": "Include flags must be boolean"
            }), 400
        
        # At least one character type must be selected
        if not any([include_uppercase, include_lowercase, include_numbers, include_symbols]):
            return jsonify({
                "error": "At least one character type must be selected"
            }), 400
        
        # Generate password
        password = generate_secure_password(
            length=length,
            include_uppercase=include_uppercase,
            include_lowercase=include_lowercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols
        )
        
        # Return generated password
        return jsonify({
            "password": password
        }), 200
        
    except Exception as e:
        # Never expose internal error details
        return jsonify({
            "error": "Unable to generate password. Please try again."
        }), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return jsonify({
        "error": "Method not allowed"
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({
        "error": "Internal server error"
    }), 500


if __name__ == '__main__':
    # Configuration for development and production
    # For local development: Flask development server with debug mode
    # For production (Render): WSGI server (Gunicorn) with environment-based config
    
    # Get environment variables
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Bind to 0.0.0.0 to allow external connections (required for Render)
    # Use localhost only for local development
    host = '127.0.0.1' if debug else '0.0.0.0'
    
    app.run(
        debug=debug,
        host=host,
        port=port,
        use_reloader=debug,
    )
