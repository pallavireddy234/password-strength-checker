# Password Strength Checker

A modern, full-stack web application that provides instant, detailed password security analysis with a beautiful, futuristic cybersecurity-inspired interface.

## Features

- **Real-Time Analysis**: Instant feedback as you type your password
- **Comprehensive Strength Scoring**: 0-100 scale with five distinct security levels
- **Security Checks**: Detailed analysis of character types, patterns, and vulnerabilities
- **Entropy Estimation**: Calculates estimated entropy (in bits) with transparent methodology
- **Smart Recommendations**: Context-aware suggestions based on password weaknesses
- **Password Generator**: Cryptographically secure password generation with customizable options
- **Premium Design**: Futuristic glassmorphism UI with smooth animations and micro-interactions
- **Fully Responsive**: Optimized for desktop, tablet, and mobile devices
- **Accessible**: Full keyboard navigation and screen reader support
- **Privacy-First**: Passwords are analyzed in-session only, never stored or logged

## Tech Stack

- **Backend**: Python 3.11+ with Flask
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Architecture**: Clean, modular, production-ready code

## Security Notes

This application:
- ✓ Does NOT store passwords
- ✓ Does NOT log passwords
- ✓ Does NOT send passwords to external services
- ✓ Performs all analysis locally in your session
- ✓ Does not use passwords in URLs or storage APIs

**Important**: This is an educational password analysis tool. While it provides a good general assessment, it should not be treated as a guarantee of password security. For maximum privacy, avoid testing passwords you currently use for sensitive accounts.

## Installation

### 1. Clone or Download the Project

```bash
git clone <repository-url>
cd password-strength-checker
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

### 3. Activate Virtual Environment

**Windows:**
```bash
venv\Scripts\activate
```

**macOS/Linux:**
```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the Application

### Primary Method

```bash
python app.py
```

### Alternative Method (Module Execution)

```bash
python -m app
```

The application will start on `http://127.0.0.1:5000` and automatically open in your default browser.

## Deployment

### Deploy to Render.com

This application is configured for easy deployment to [Render.com](https://render.com), a modern cloud platform.

#### Prerequisites
- GitHub account (to host the repository)
- Render.com account (free tier available)

#### Steps

1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Password Strength Checker"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/password-strength-checker.git
   git push -u origin main
   ```

2. **Create a new Web Service on Render:**
   - Go to [dashboard.render.com](https://dashboard.render.com)
   - Click "New +"
   - Select "Web Service"
   - Connect your GitHub repository
   - Choose the repository `password-strength-checker`

3. **Configure the service:**
   - **Name**: `password-strength-checker` (or your preferred name)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Free (or paid for better performance)

4. **Set Environment Variables (Optional):**
   - Go to "Environment" in the service settings
   - Add `FLASK_ENV` = `production` (already configured in render.yaml)

5. **Deploy:**
   - Render automatically deploys when you push to the main branch
   - Your app will be available at `https://your-app-name.onrender.com`

#### Automatic Deployment Configuration

The project includes:
- **Procfile**: Specifies how to run the app with Gunicorn
- **render.yaml**: Render-specific configuration file
- **requirements.txt**: Includes Gunicorn for production

No additional configuration needed! Just connect your GitHub repo to Render.

#### Environment Variables for Production

Render automatically sets:
- `PORT`: The port your app should listen on (handled by app.py)
- `FLASK_ENV`: Set to `production` (see render.yaml)

Your app will automatically bind to `0.0.0.0` and use the correct port.

#### Notes

- Free tier on Render spins down after 15 minutes of inactivity
- For production use, upgrade to a paid plan for always-on service
- The application uses no database, so free tier is sufficient
- All password analysis happens in-session with no storage

## Usage

1. **Analyze Password**: Type any password into the input field
2. **View Results**: Real-time analysis shows:
   - Strength score (0-100)
   - Security level (Very Weak, Weak, Fair, Strong, Very Strong)
   - Character composition checks
   - Detected patterns and weaknesses
   - Estimated entropy
   - Actionable recommendations
3. **Generate Password**: Click "Generate Strong Password" to create a secure random password
4. **Customize Generation**: Select desired character types and length
5. **Copy to Clipboard**: Use the "Copy" button to copy generated passwords

## Project Structure

```
password-strength-checker/
├── app.py                          # Flask application entry point
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── .gitignore                      # Git ignore rules
│
├── backend/
│   ├── __init__.py                # Package initialization
│   └── password_analyzer.py       # Password analysis engine
│
├── templates/
│   └── index.html                 # Main HTML template
│
└── static/
    ├── css/
    │   └── style.css              # Styling and animations
    └── js/
        └── app.js                 # Frontend logic and interactivity
```

## API Endpoints

### GET /
Returns the main HTML interface.

### POST /api/analyze
Analyzes a password and returns security metrics.

**Request:**
```json
{
  "password": "your-password-here"
}
```

**Response:**
```json
{
  "score": 72,
  "level": "Strong",
  "entropy": 48.2,
  "length": 16,
  "checks": {
    "length": true,
    "uppercase": true,
    "lowercase": true,
    "numbers": true,
    "symbols": true,
    "common_password": false,
    "repeated_characters": false,
    "sequential_characters": false
  },
  "suggestions": [
    "Great password length",
    "Excellent character diversity"
  ]
}
```

### POST /api/generate
Generates a cryptographically secure random password.

**Request:**
```json
{
  "length": 16,
  "include_uppercase": true,
  "include_lowercase": true,
  "include_numbers": true,
  "include_symbols": true
}
```

**Response:**
```json
{
  "password": "aB3$xYzQ9@mNpLkJ"
}
```

## Password Analysis Methodology

### Scoring Algorithm

The password score (0-100) is calculated based on:

1. **Length Factor**: Rewards longer passwords (minimum effective length: 6 characters)
2. **Character Diversity**: Bonus for including uppercase, lowercase, numbers, and symbols
3. **Entropy Calculation**: Based on character pool size and length
4. **Pattern Analysis**: Penalties for:
   - Common passwords (top 1000 list)
   - Sequential characters (e.g., "123456", "abcdef")
   - Keyboard patterns (e.g., "qwerty", "asdf")
   - Excessive character repetition
   - Obvious substitutions (e.g., "p@ssw0rd")

### Score Ranges

- **0-19**: Very Weak - High security risk
- **20-39**: Weak - Moderate vulnerability
- **40-59**: Fair - Acceptable but could be improved
- **60-79**: Strong - Good security level
- **80-100**: Very Strong - Excellent security level

### Entropy Calculation

Entropy is estimated using the formula:
```
entropy = length × log₂(character_pool_size) × effective_diversity_multiplier
```

Where `character_pool_size` is determined by:
- Lowercase letters: 26
- Uppercase letters: 26
- Digits: 10
- Symbols: varies by set used

Entropy is reduced when predictable patterns are detected.

**Note**: This is an approximation based on classical password entropy theory and does not account for all possible attack vectors.

## Security Checks

The application checks for:

- ✓ Minimum length (8+ characters recommended)
- ✓ Uppercase letters (A-Z)
- ✓ Lowercase letters (a-z)
- ✓ Numeric characters (0-9)
- ✓ Special symbols (!@#$%^&*)
- ✓ Common passwords (top 1000 vulnerable passwords)
- ✓ Sequential characters (123, abc, qwerty patterns)
- ✓ Repeated characters (aaaa, 1111)
- ✓ Keyboard patterns (qwerty, asdf, zxcv)

## Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Performance

- First load: <500ms
- Password analysis: <100ms (with 150ms debounce)
- No external dependencies on loading
- Optimized for modern browsers

## Accessibility

- Full keyboard navigation
- ARIA labels and roles
- High contrast color scheme
- Respects `prefers-reduced-motion` media query
- Semantic HTML
- Screen reader friendly

## Development

### Local Development

1. Activate virtual environment
2. Run `python app.py`
3. Edit files in `backend/`, `templates/`, or `static/`
4. Refresh browser to see changes (Flask debug mode enabled)

### Adding More Security Checks

Edit `backend/password_analyzer.py` and add to the `analyze()` method.

### Customizing Design

Edit `static/css/style.css` to modify colors, animations, and layout. CSS variables are defined at the top for easy theme customization.

## Troubleshooting

### Port Already in Use
Change the port in `app.py`:
```python
app.run(debug=True, host='127.0.0.1', port=5001)
```

### Module Import Errors
Ensure virtual environment is activated and dependencies are installed:
```bash
pip install -r requirements.txt
```

### Frontend Not Updating
Clear browser cache (Ctrl+Shift+Delete) and hard refresh (Ctrl+F5).

## License

This project is provided as-is for educational and personal use.

## Support

For issues or suggestions, please refer to the code comments and documentation within each file.

---

**Last Updated**: 2026-08-29
