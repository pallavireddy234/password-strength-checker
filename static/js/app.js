/*
 * Password Strength Checker - Frontend Application
 * 
 * Handles real-time password analysis, UI updates,
 * password generation, and user interactions.
 * 
 * Security Note: Passwords are analyzed locally in this session only.
 * No passwords are stored, logged, or sent to external services.
 */

// ============================================================================
// DOM Elements
// ============================================================================

const passwordInput = document.getElementById('password-input');
const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
const clearBtn = document.getElementById('clear-btn');

const initialState = document.getElementById('initial-state');
const analysisState = document.getElementById('analysis-state');
const errorState = document.getElementById('error-state');

const strengthBar = document.getElementById('strength-bar');
const strengthLevel = document.getElementById('strength-level');
const strengthScore = document.getElementById('strength-score');

const checkLength = document.getElementById('check-length');
const checkUppercase = document.getElementById('check-uppercase');
const checkLowercase = document.getElementById('check-lowercase');
const checkNumbers = document.getElementById('check-numbers');
const checkSymbols = document.getElementById('check-symbols');
const checkCommon = document.getElementById('check-common');
const checkRepetition = document.getElementById('check-repetition');
const checkSequential = document.getElementById('check-sequential');

const entropyValue = document.getElementById('entropy-value');
const entropyBar = document.getElementById('entropy-bar');
const entropyTooltip = document.getElementById('entropy-tooltip');
const infoBtn = document.querySelector('.info-btn');

const recommendationsList = document.getElementById('recommendations-list');
const errorMessage = document.getElementById('error-message');

// Generator elements
const lengthSlider = document.getElementById('length-slider');
const lengthInput = document.getElementById('length-input');
const genUppercase = document.getElementById('gen-uppercase');
const genLowercase = document.getElementById('gen-lowercase');
const genNumbers = document.getElementById('gen-numbers');
const genSymbols = document.getElementById('gen-symbols');
const generatedPasswordDisplay = document.getElementById('generated-password');
const generateBtn = document.getElementById('generate-btn');
const copyPasswordBtn = document.getElementById('copy-password-btn');
const copyFeedback = document.getElementById('copy-feedback');

// ============================================================================
// Configuration & State
// ============================================================================

const CONFIG = {
    DEBOUNCE_DELAY: 200,  // ms
    ENTROPY_MAX_DISPLAY: 128,  // bits for visual scaling
};

let debounceTimer = null;
let lastPassword = '';

// ============================================================================
// Event Listeners
// ============================================================================

// Password input events
passwordInput.addEventListener('input', handlePasswordInput);
passwordInput.addEventListener('focus', () => clearBtn.classList.add('visible'));
passwordInput.addEventListener('blur', () => {
    if (!passwordInput.value) {
        clearBtn.classList.remove('visible');
    }
});

// Toggle visibility
toggleVisibilityBtn.addEventListener('click', togglePasswordVisibility);
toggleVisibilityBtn.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        togglePasswordVisibility();
    }
});

// Clear button
clearBtn.addEventListener('click', clearPasswordInput);

// Entropy info button
infoBtn.addEventListener('click', toggleEntropyTooltip);
document.addEventListener('click', (e) => {
    if (!e.target.closest('.entropy-section')) {
        entropyTooltip.classList.add('hidden');
    }
});

// Generator controls
lengthSlider.addEventListener('input', syncLengthInputs);
lengthInput.addEventListener('input', syncLengthInputs);

genUppercase.addEventListener('change', regeneratePassword);
genLowercase.addEventListener('change', regeneratePassword);
genNumbers.addEventListener('change', regeneratePassword);
genSymbols.addEventListener('change', regeneratePassword);

generateBtn.addEventListener('click', handleGeneratePassword);
copyPasswordBtn.addEventListener('click', copyPasswordToClipboard);

// ============================================================================
// Password Input Handler
// ============================================================================

function handlePasswordInput(e) {
    const password = passwordInput.value;
    
    // Show/hide clear button
    if (password) {
        clearBtn.classList.add('visible');
    } else {
        clearBtn.classList.remove('visible');
    }
    
    // Clear existing debounce timer
    if (debounceTimer) {
        clearTimeout(debounceTimer);
    }
    
    // Debounce the analysis
    debounceTimer = setTimeout(() => {
        analyzePassword(password);
    }, CONFIG.DEBOUNCE_DELAY);
}

// ============================================================================
// Password Analysis
// ============================================================================

async function analyzePassword(password) {
    // Don't analyze if password hasn't changed
    if (password === lastPassword) {
        return;
    }
    
    lastPassword = password;
    
    // Show initial state if password is empty
    if (!password) {
        showInitialState();
        return;
    }
    
    try {
        // Send request to backend
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password: password })
        });
        
        if (!response.ok) {
            throw new Error('Analysis failed');
        }
        
        const data = await response.json();
        
        // Update UI with results
        updateAnalysisUI(data);
        showAnalysisState();
        
    } catch (error) {
        console.error('Error analyzing password:', error);
        showErrorState('Unable to analyze password. Please try again.');
    }
}

function updateAnalysisUI(data) {
    // Update strength score and level
    updateStrengthMeter(data.score, data.level);
    
    // Update security checks
    updateSecurityChecks(data.checks);
    
    // Update entropy
    updateEntropy(data.entropy);
    
    // Update recommendations
    updateRecommendations(data.suggestions);
}

function updateStrengthMeter(score, level) {
    // Update bar width
    strengthBar.style.width = score + '%';
    
    // Update level text with appropriate color
    strengthLevel.textContent = level.toUpperCase();
    strengthLevel.className = 'strength-level ' + level.toLowerCase().replace(' ', '-');
    
    // Update score display with animation
    const oldScore = parseInt(strengthScore.textContent) || 0;
    if (oldScore !== score) {
        animateNumber(strengthScore, oldScore, score);
    }
}

function animateNumber(element, from, to) {
    const duration = 300;  // ms
    const startTime = Date.now();
    
    function step() {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = Math.floor(from + (to - from) * progress);
        element.textContent = current + ' / 100';
        
        if (progress < 1) {
            requestAnimationFrame(step);
        }
    }
    
    requestAnimationFrame(step);
}

function updateSecurityChecks(checks) {
    // Map of check elements
    const checkElements = {
        'length': checkLength,
        'uppercase': checkUppercase,
        'lowercase': checkLowercase,
        'numbers': checkNumbers,
        'symbols': checkSymbols,
        'common_password': checkCommon,
        'repeated_characters': checkRepetition,
        'sequential_characters': checkSequential,
    };
    
    // Update each check
    for (const [checkName, element] of Object.entries(checkElements)) {
        const isPassed = checks[checkName];
        const checkItem = element.closest('.check-item');
        
        // Update classes
        checkItem.classList.remove('passed', 'failed');
        if (isPassed) {
            checkItem.classList.add('passed');
            element.textContent = '✓';
            element.style.animation = 'none';
            setTimeout(() => {
                element.style.animation = '';
            }, 0);
        } else {
            checkItem.classList.add('failed');
            element.textContent = '✕';
            element.style.animation = 'none';
            setTimeout(() => {
                element.style.animation = '';
            }, 0);
        }
    }
}

function updateEntropy(entropy) {
    entropyValue.textContent = entropy;
    
    // Scale entropy for visual display (max 128 bits)
    const entropyPercent = Math.min((entropy / CONFIG.ENTROPY_MAX_DISPLAY) * 100, 100);
    entropyBar.style.width = entropyPercent + '%';
}

function updateRecommendations(suggestions) {
    recommendationsList.innerHTML = '';
    
    if (suggestions.length === 0) {
        recommendationsList.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: var(--spacing-md);">No recommendations</div>';
        return;
    }
    
    suggestions.forEach((suggestion) => {
        const item = document.createElement('div');
        item.className = 'recommendation-item';
        item.textContent = '• ' + suggestion;
        recommendationsList.appendChild(item);
    });
}

// ============================================================================
// UI State Management
// ============================================================================

function showInitialState() {
    initialState.classList.remove('hidden');
    analysisState.classList.add('hidden');
    errorState.classList.add('hidden');
}

function showAnalysisState() {
    initialState.classList.add('hidden');
    analysisState.classList.remove('hidden');
    errorState.classList.add('hidden');
}

function showErrorState(message) {
    initialState.classList.add('hidden');
    analysisState.classList.add('hidden');
    errorState.classList.remove('hidden');
    errorMessage.textContent = message;
}

// ============================================================================
// Password Visibility Toggle
// ============================================================================

function togglePasswordVisibility() {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    
    // Update button appearance
    toggleVisibilityBtn.classList.toggle('visible');
    toggleVisibilityBtn.setAttribute('aria-pressed', isPassword);
}

// ============================================================================
// Clear Password
// ============================================================================

function clearPasswordInput() {
    passwordInput.value = '';
    clearBtn.classList.remove('visible');
    passwordInput.focus();
    
    // Clear analysis
    showInitialState();
    lastPassword = '';
    
    // Clear debounce timer
    if (debounceTimer) {
        clearTimeout(debounceTimer);
    }
}

// ============================================================================
// Entropy Tooltip
// ============================================================================

function toggleEntropyTooltip(e) {
    e.stopPropagation();
    entropyTooltip.classList.toggle('hidden');
}

// ============================================================================
// Password Generation
// ============================================================================

function syncLengthInputs(e) {
    const value = e.target.value;
    lengthSlider.value = value;
    lengthInput.value = value;
    regeneratePassword();
}

async function handleGeneratePassword() {
    generateBtn.disabled = true;
    generateBtn.textContent = '⏳ Generating...';
    
    try {
        await regeneratePassword();
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = '⚡ Generate Password';
    }
}

async function regeneratePassword() {
    try {
        const length = parseInt(lengthInput.value) || 16;
        const includeUppercase = genUppercase.checked;
        const includeLowercase = genLowercase.checked;
        const includeNumbers = genNumbers.checked;
        const includeSymbols = genSymbols.checked;
        
        // Validate at least one option is selected
        if (!includeUppercase && !includeLowercase && !includeNumbers && !includeSymbols) {
            alert('Please select at least one character type');
            genLowercase.checked = true;
            return;
        }
        
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                length: length,
                include_uppercase: includeUppercase,
                include_lowercase: includeLowercase,
                include_numbers: includeNumbers,
                include_symbols: includeSymbols,
            })
        });
        
        if (!response.ok) {
            throw new Error('Generation failed');
        }
        
        const data = await response.json();
        generatedPasswordDisplay.textContent = data.password;
        
    } catch (error) {
        console.error('Error generating password:', error);
        generatedPasswordDisplay.textContent = 'Generation failed';
    }
}

// ============================================================================
// Copy to Clipboard
// ============================================================================

async function copyPasswordToClipboard() {
    const password = generatedPasswordDisplay.textContent;
    
    if (!password || password === 'Generation failed' || password === '••••••••••••••••') {
        alert('Please generate a password first');
        return;
    }
    
    try {
        // Use modern Clipboard API
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(password);
        } else {
            // Fallback for older browsers
            copyToClipboardFallback(password);
        }
        
        // Show feedback
        copyFeedback.classList.remove('hidden');
        setTimeout(() => {
            copyFeedback.classList.add('hidden');
        }, 1500);
        
    } catch (error) {
        console.error('Error copying to clipboard:', error);
        alert('Failed to copy password');
    }
}

function copyToClipboardFallback(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
}

// ============================================================================
// Initialization
// ============================================================================

function initialize() {
    // Set initial password length display
    generatedPasswordDisplay.textContent = '••••••••••••••••';
    
    // Generate initial password
    regeneratePassword();
    
    // Focus on password input
    passwordInput.focus();
    
    // Log that app is ready (without any password info)
    console.log('Password Strength Checker initialized');
}

// Run initialization when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

// ============================================================================
// Accessibility Enhancements
// ============================================================================

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Alt+C to clear password
    if (e.altKey && e.key === 'c') {
        e.preventDefault();
        clearPasswordInput();
    }
    
    // Alt+G to generate password
    if (e.altKey && e.key === 'g') {
        e.preventDefault();
        handleGeneratePassword();
    }
});

// Announce analysis results for screen readers
function announceResults(level, score) {
    const announcement = document.createElement('div');
    announcement.setAttribute('role', 'status');
    announcement.setAttribute('aria-live', 'polite');
    announcement.className = 'sr-only';
    announcement.textContent = `Password strength: ${level}, Score: ${score} out of 100`;
    document.body.appendChild(announcement);
    
    // Remove after announcement
    setTimeout(() => {
        document.body.removeChild(announcement);
    }, 1000);
}

// ============================================================================
// Error Handling
// ============================================================================

window.addEventListener('error', (event) => {
    console.error('Uncaught error:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});
