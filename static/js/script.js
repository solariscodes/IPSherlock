document.addEventListener('DOMContentLoaded', function() {
    // Add click handlers for collapsible sections
    const collapsibleSections = document.querySelectorAll('.result-section h3');
    
    collapsibleSections.forEach(section => {
        section.addEventListener('click', function() {
            const content = this.nextElementSibling;
            
            // Toggle the visibility of the content
            if (content.classList.contains('collapsible-content')) {
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + 'px';
                }
            }
        });
    });
    
    // Form validation and loading indicator
    const form = document.getElementById('lookup-form');
    const loadingIndicator = document.getElementById('loading-indicator');
    
    // Reset form state when page loads (handles browser back button)
    const submitButton = document.getElementById('lookup-button');
    if (submitButton) {
        submitButton.disabled = false;
        submitButton.innerHTML = 'Lookup';
    }
    
    if (form) {
        // Reset the form on page load
        form.reset();
        
        // Function to validate IP address (IPv4 or IPv6)
        function isValidIP(ip) {
            // Check if this might be an IPv6 address (contains colons)
            if (ip.includes(':')) {
                // Basic IPv6 validation - at least 2 colons and valid hex characters
                // This is a simplified check - the server will do a more thorough validation
                const ipv6Pattern = /^[0-9a-fA-F:]+$/;
                return ipv6Pattern.test(ip) && ip.includes('::') || ip.split(':').length > 2;
            }
            
            // IPv4 validation
            const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipPattern.test(ip)) return false;
            
            // Check that each octet is between 0 and 255
            const octets = ip.split('.');
            for (const octet of octets) {
                const num = parseInt(octet, 10);
                if (num < 0 || num > 255) return false;
            }
            return true;
        }
        
        // Function to strip protocols from URLs
        function stripProtocols(url) {
            const protocols = ['http://', 'https://', 'ftp://', 'ftps://'];
            for (const protocol of protocols) {
                if (url.startsWith(protocol)) {
                    url = url.substring(protocol.length);
                    break;
                }
            }
            
            // Also remove any trailing path or query parameters
            url = url.split('/', 1)[0].split('?', 1)[0];
            
            return url;
        }
        
        // Function to validate domain name
        function isValidDomain(domain) {
            // Strip protocols first
            domain = stripProtocols(domain);
            
            // Must have at least one dot
            if (domain.indexOf('.') === -1) return false;
            
            // Check TLD length (at least 2 chars)
            const parts = domain.split('.');
            if (parts[parts.length - 1].length < 2) return false;
            
            // Domain name pattern
            const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
            return domainPattern.test(domain);
        }
        
        form.addEventListener('submit', function(e) {
            const queryInput = document.getElementById('query');
            const query = queryInput.value.trim();
            
            if (!query) {
                e.preventDefault();
                queryInput.classList.add('error');
                showError('Please enter an IP address or domain name.');
                return false;
            }
            
            // Strip protocols before validation
            const cleanQuery = stripProtocols(query);
            
            // Validate the query format
            if (!isValidIP(cleanQuery) && !isValidDomain(cleanQuery)) {
                e.preventDefault();
                queryInput.classList.add('error');
                showError('Please enter a valid IP address (like 8.8.8.8 or 2001:4860:4860::8888) or domain name (like example.com).');
                return false;
            }
            
            // Show loading indicator
            if (loadingIndicator) {
                loadingIndicator.style.display = 'flex';
                
                // Disable the submit button to prevent multiple submissions
                if (submitButton) {
                    submitButton.disabled = true;
                    submitButton.innerHTML = 'Looking up...';
                }
            }
            
            return true;
        });
        
        // Function to show error message
        function showError(message) {
            let errorDiv = document.querySelector('.error-message');
            if (!errorDiv) {
                errorDiv = document.createElement('div');
                errorDiv.className = 'error-message';
                
                const icon = document.createElement('i');
                icon.className = 'fas fa-exclamation-circle';
                errorDiv.appendChild(icon);
                
                const span = document.createElement('span');
                errorDiv.appendChild(span);
                
                // Insert after the input group
                const inputGroup = document.querySelector('.input-group');
                inputGroup.parentNode.insertBefore(errorDiv, inputGroup.nextSibling);
            }
            
            // Update the error message
            errorDiv.querySelector('span').textContent = message;
        }
    }
    
    // Remove error class on input focus
    const queryInput = document.getElementById('query');
    if (queryInput) {
        queryInput.addEventListener('focus', function() {
            this.classList.remove('error');
        });
    }
    
    // Hide loading indicator when page is fully loaded
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
    
    // Handle the browser back button specifically
    window.addEventListener('pageshow', function(event) {
        // When navigating back, the pageshow event fires with persisted property
        if (event.persisted) {
            // Reset the form and button state
            if (form) form.reset();
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.innerHTML = 'Lookup';
            }
            if (loadingIndicator) {
                loadingIndicator.style.display = 'none';
            }
        }
    });
});

// Function to copy WHOIS data to clipboard
function copyToClipboard() {
    // Get the pre element containing the WHOIS data
    const whoisData = document.querySelector('.collapsible-content pre').textContent;
    
    // Create a temporary textarea element to copy from
    const textarea = document.createElement('textarea');
    textarea.value = whoisData;
    document.body.appendChild(textarea);
    
    // Select and copy the text
    textarea.select();
    document.execCommand('copy');
    
    // Remove the temporary textarea
    document.body.removeChild(textarea);
    
    // Show success feedback
    const copyBtn = document.querySelector('.copy-btn');
    const originalIcon = copyBtn.innerHTML;
    
    // Change to checkmark icon
    copyBtn.innerHTML = '<i class="fas fa-check"></i>';
    copyBtn.classList.add('success');
    
    // Reset after 2 seconds
    setTimeout(() => {
        copyBtn.innerHTML = originalIcon;
        copyBtn.classList.remove('success');
    }, 2000);
}
