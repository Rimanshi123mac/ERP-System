/**
 * CSRF Token Helper
 * Automatically includes CSRF token in all AJAX requests
 */

// Get CSRF token from meta tag or cookie
function getCSRFToken() {
    // Try to get from meta tag first
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (metaTag) {
        return metaTag.getAttribute('content');
    }
    
    // Fallback: try to get from cookie (if set)
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'csrf_token') {
            return value;
        }
    }
    
    return null;
}

// Override fetch to automatically include CSRF token
const originalFetch = window.fetch;
window.fetch = function(url, options = {}) {
    // Only add CSRF token for POST, PUT, DELETE, PATCH requests
    if (options.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method.toUpperCase())) {
        const token = getCSRFToken();
        if (token) {
            // Set headers if not already set
            if (!options.headers) {
                options.headers = {};
            }
            
            // Handle both Headers object and plain object
            if (options.headers instanceof Headers) {
                options.headers.set('X-CSRF-Token', token);
            } else {
                options.headers['X-CSRF-Token'] = token;
            }
        }
    }
    
    return originalFetch(url, options);
};

// Helper function to add CSRF token to form data
function addCSRFTokenToForm(formData) {
    const token = getCSRFToken();
    if (token) {
        formData.append('csrf_token', token);
    }
    return formData;
}

// Helper function to add CSRF token to JSON data
function addCSRFTokenToJSON(data) {
    const token = getCSRFToken();
    if (token) {
        data.csrf_token = token;
    }
    return data;
}

// Export for use in other scripts
window.CSRFHelper = {
    getToken: getCSRFToken,
    addToForm: addCSRFTokenToForm,
    addToJSON: addCSRFTokenToJSON
};

