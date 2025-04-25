from flask import Flask, render_template, request, redirect, url_for, Response, session, send_from_directory, send_file
import socket
import whois
import dns.resolver
import requests
import re
from ipwhois import IPWhois
import csv
import io
import os
import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Use a non-obvious environment variable name for admin access
# SHERLOCK_CASE_FILE is our secure, non-obvious environment variable name
ADMIN_PASSWORD = os.environ.get('SHERLOCK_CASE_FILE', 'default_admin_key_please_change')

# Print a reminder if using the default password
if os.environ.get('RAILWAY_ENVIRONMENT') and ADMIN_PASSWORD == 'default_admin_key_please_change':
    print("\n\n==== SECURITY WARNING ====")
    print("Please set the SHERLOCK_CASE_FILE environment variable in Railway!")
    print("==== SECURITY WARNING ====\n\n")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ipsherlock_detective_secret_key')
app.config['SESSION_TYPE'] = 'filesystem'

# Define constants for log storage
LOG_FILENAME = 'railway_logs.txt'
ACCESS_LOG_FILENAME = 'access.log'
MAX_LOGS = 1000  # Maximum number of logs to store

# Setup logging - place logs in a secure location outside web root
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

# Create a .htaccess file to prevent direct web access to logs directory
htaccess_path = os.path.join(log_dir, '.htaccess')
if not os.path.exists(htaccess_path):
    try:
        with open(htaccess_path, 'w') as f:
            f.write("# Prevent direct access to log files\n")
            f.write("Order deny,allow\n")
            f.write("Deny from all\n")
    except Exception as e:
        print(f"Could not create .htaccess file: {e}")

# Create a custom logger for searches
search_logger = logging.getLogger('search_logger')
search_logger.setLevel(logging.INFO)

# Prevent the logger from propagating to the root logger
search_logger.propagate = False

# Create handlers
search_log_file = os.path.join(log_dir, 'search.log')
handler = RotatingFileHandler(search_log_file, maxBytes=10485760, backupCount=10)  # 10MB per file, keep 10 files
handler.setLevel(logging.INFO)

# Create formatters and add it to handlers
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)

# Add handlers to the logger
search_logger.addHandler(handler)

# Script logging has been removed

# Create a logger for HTTP access logs (Apache-style)
access_logger = logging.getLogger('access_logger')
access_logger.setLevel(logging.INFO)
access_logger.propagate = False

# Create a handler for access logs
access_log_file = os.path.join(log_dir, 'access.log')
access_handler = RotatingFileHandler(access_log_file, maxBytes=10485760, backupCount=10)  # 10MB per file, keep 10 files
access_handler.setLevel(logging.INFO)

# Create a simple formatter for access logs (Apache-like format)
access_formatter = logging.Formatter('%(message)s')
access_handler.setFormatter(access_formatter)

# Add handler to the access logger
access_logger.addHandler(access_handler)

# Script logging has been removed

# Log all HTTP requests in Apache-like format
@app.before_request
def log_request():
    # Get client IP, handling proxy headers
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    else:
        client_ip = request.remote_addr
        
    # Determine if this is IPv4 or IPv6
    ip_version = "IPv6" if ':' in client_ip else "IPv4"
    
    # Get current timestamp in a clean format
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Get the request method and full path with query string
    method = request.method
    full_path = request.full_path if request.query_string else request.path
    
    # Get user agent
    user_agent = request.headers.get('User-Agent', '-')
    
    # Get referrer
    referrer = request.headers.get('Referer', '-')
    
    # Create simplified log entry
    # Format: <ip> | <datetime> | <uri> | <browser>
    # This is a cleaner format focusing only on the essential information
    
    # Store the log info in the request object for use in after_request
    request.log_info = {
        'client_ip': client_ip,
        'ip_version': "IPv6" if ':' in client_ip else "IPv4",
        'timestamp': timestamp,
        'method': method,
        'path': full_path,
        'referrer': referrer,
        'user_agent': user_agent
    }
    
    # Continue logging specific search queries for backward compatibility
    if request.path == '/results' and 'query' in request.args:
        query = request.args.get('query', '').strip()
        if query:
            # Create log entry in same format as before
            old_timestamp = datetime.now().strftime('[%d/%b/%Y %H:%M:%S]')
            log_entry = f"{client_ip} - - {old_timestamp} \"GET /results?query={query} HTTP/1.1\" 200 -"
            
            # For Railway: Store in tmp directory which is ephemeral but works during the session
            if os.environ.get('RAILWAY_ENVIRONMENT'):
                try:
                    # Use a file in /tmp which is writable on Railway
                    log_file = os.path.join('/tmp', LOG_FILENAME)
                    
                    # Read existing logs (if any)
                    logs = []
                    if os.path.exists(log_file):
                        with open(log_file, 'r', encoding='utf-8') as f:
                            logs = f.readlines()
                    
                    # Add new log and keep only the most recent MAX_LOGS
                    logs.append(log_entry + '\n')
                    logs = logs[-MAX_LOGS:]
                    
                    # Write back to file
                    with open(log_file, 'w', encoding='utf-8') as f:
                        f.writelines(logs)
                except Exception as e:
                    print(f"Railway logging error: {e}")
            
            # For local development: Use the logs directory
            else:
                try:
                    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
                    os.makedirs(log_dir, exist_ok=True)
                    log_file = os.path.join(log_dir, 'search.log')
                    
                    with open(log_file, 'a', encoding='utf-8') as f:
                        f.write(log_entry + '\n')
                        f.flush()
                        os.fsync(f.fileno())  # Force write to disk
                except Exception as e:
                    print(f"Logging error: {e}")

# Complete the Apache-style logging after the request is processed
@app.after_request
def after_request(response):
    # Always ensure we have log_info for every request
    if not hasattr(request, 'log_info'):
        # Get client IP, handling proxy headers
        if request.headers.get('X-Forwarded-For'):
            client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        else:
            client_ip = request.remote_addr
        
        # Get current timestamp in Apache log format
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Get the request method and full path with query string
        method = request.method
        full_path = request.full_path if request.query_string else request.path
        
        # Get user agent
        user_agent = request.headers.get('User-Agent', '-')
        
        # Get referrer
        referrer = request.headers.get('Referer', '-')
        
        # Create the log_info if it doesn't exist
        request.log_info = {
            'client_ip': client_ip,
            'ip_version': "IPv6" if ':' in client_ip else "IPv4",
            'timestamp': timestamp,
            'method': method,
            'path': full_path,
            'referrer': referrer,
            'user_agent': user_agent
        }
    
    # Get response status code
    status_code = response.status_code
    
    # Get response size (content length)
    response_size = response.content_length if response.content_length is not None else '-'
    
    # Format a simplified log entry with only the essential information
    # Get the URI without the domain
    uri = request.log_info['path'].replace('http://localhost:5000/', '/')
    if uri.startswith('http'):
        # Extract just the path from any full URL
        uri = '/' + uri.split('/', 3)[3] if len(uri.split('/', 3)) > 3 else '/'
    
    # Format date and time in a cleaner way
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Extract operating system information from user agent
    user_agent = request.log_info['user_agent']
    os_info = "Unknown"
    
    # Simple OS detection from user agent
    if "Windows" in user_agent:
        os_version = re.search(r'Windows NT (\d+\.\d+)', user_agent)
        if os_version:
            nt_version = os_version.group(1)
            os_mapping = {
                '10.0': 'Windows 10/11',
                '6.3': 'Windows 8.1',
                '6.2': 'Windows 8',
                '6.1': 'Windows 7',
                '6.0': 'Windows Vista',
                '5.2': 'Windows XP x64',
                '5.1': 'Windows XP',
            }
            os_info = os_mapping.get(nt_version, f"Windows NT {nt_version}")
        else:
            os_info = "Windows"
    elif "Macintosh" in user_agent:
        if "Intel Mac OS X" in user_agent:
            mac_version = re.search(r'Intel Mac OS X (\d+[._]\d+)', user_agent)
            if mac_version:
                os_info = f"macOS {mac_version.group(1).replace('_', '.')}" 
            else:
                os_info = "macOS"
        else:
            os_info = "macOS"
    elif "Linux" in user_agent:
        if "Android" in user_agent:
            android_version = re.search(r'Android (\d+\.\d+)', user_agent)
            if android_version:
                os_info = f"Android {android_version.group(1)}"
            else:
                os_info = "Android"
        else:
            os_info = "Linux"
    elif "iPhone" in user_agent or "iPad" in user_agent or "iPod" in user_agent:
        ios_version = re.search(r'OS (\d+[._]\d+)', user_agent)
        if ios_version:
            os_info = f"iOS {ios_version.group(1).replace('_', '.')}"
        else:
            os_info = "iOS"
    
    # Get browser name
    browser = request.log_info['user_agent'].split(' ')[0]
    
    # Create a clean log entry with IP, IP version, date/time, URI, OS, and browser
    log_entry = f"{request.log_info['client_ip']} ({request.log_info['ip_version']}) | {timestamp} | {uri} | {os_info} | {browser}"
    
    # Log to access logger
    access_logger.info(log_entry)
    
    # For Railway: Store in tmp directory
    if os.environ.get('RAILWAY_ENVIRONMENT'):
        try:
            access_log_file = os.path.join('/tmp', ACCESS_LOG_FILENAME)
            with open(access_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + '\n')
        except Exception as e:
            print(f"Railway access logging error: {e}")
    
    return response

def is_valid_ip(ip):
    """Check if the input is a valid IP address (IPv4 or IPv6)."""
    # First, try to clean up the input - remove any surrounding brackets which might be present
    ip = ip.strip('[]')
    
    # Check for IPv4
    if ':' not in ip:
        # IPv4 pattern
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ipv4_pattern.match(ip):
            return False
        # Check that each octet is between 0 and 255
        octets = ip.split('.')
        for octet in octets:
            if int(octet) < 0 or int(octet) > 255:
                return False
        return True
    else:
        # IPv6 validation using socket library
        try:
            # This will validate the IPv6 address format
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except (socket.error, ValueError):
            # Try one more time with any potential URL encoding fixed
            try:
                # Replace encoded characters that might appear in IPv6 addresses
                fixed_ip = ip.replace('%3A', ':')
                socket.inet_pton(socket.AF_INET6, fixed_ip)
                return True
            except (socket.error, ValueError):
                return False

def is_valid_hostname(hostname):
    """Check if the input is a valid hostname."""
    if len(hostname) > 255:
        return False
    
    # Must have at least one dot to be a domain name
    if '.' not in hostname:
        return False
        
    # Check for valid TLD (at least 2 characters after the last dot)
    parts = hostname.split('.')
    if len(parts[-1]) < 2:
        return False
    
    # Stricter pattern for hostnames
    hostname_pattern = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]{2,}|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')
    return bool(hostname_pattern.match(hostname))

def get_ip_info(ip):
    """Get detailed information about an IP address (IPv4 or IPv6)."""
    try:
        # Determine if this is IPv4 or IPv6
        ip_version = "IPv6" if ':' in ip else "IPv4"
        
        # Basic IP info
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        
        # Prepare the data with basic info
        ip_data = {
            "ip": ip,
            "ip_version": ip_version,
            "asn": results.get("asn", "N/A"),
            "asn_description": results.get("asn_description", "N/A"),
            "network": results.get("network", {}).get("cidr", "N/A"),
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "postal": "N/A",
            "latitude": None,
            "longitude": None,
            "timezone": "N/A",
            "org": results.get("asn_description", "N/A"),
            "isp": results.get("asn_description", "N/A"),
            "os_tools": {}
        }
        
        # Try multiple geolocation services
        geo_success = False
        
        # First try ipapi.co
        try:
            geo_response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                # Update with geolocation data if available
                ip_data.update({
                    "country": geo_data.get("country_name", "N/A"),
                    "region": geo_data.get("region", "N/A"),
                    "city": geo_data.get("city", "N/A"),
                    "postal": geo_data.get("postal", "N/A"),
                    "latitude": float(geo_data.get("latitude")) if geo_data.get("latitude") not in (None, "N/A") else None,
                    "longitude": float(geo_data.get("longitude")) if geo_data.get("longitude") not in (None, "N/A") else None,
                    "timezone": geo_data.get("timezone", "N/A"),
                    "org": geo_data.get("org", ip_data["org"]),
                })
                geo_success = True
        except Exception as e:
            # If ipapi.co fails, try alternative service
            first_error = str(e)
            
            # Try IP-API as fallback
            try:
                fallback_response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if fallback_response.status_code == 200:
                    fallback_data = fallback_response.json()
                    if fallback_data.get("status") == "success":
                        # Update with geolocation data from fallback
                        ip_data.update({
                            "country": fallback_data.get("country", "N/A"),
                            "region": fallback_data.get("regionName", "N/A"),
                            "city": fallback_data.get("city", "N/A"),
                            "postal": fallback_data.get("zip", "N/A"),
                            "latitude": float(fallback_data.get("lat")) if fallback_data.get("lat") not in (None, "N/A") else None,
                            "longitude": float(fallback_data.get("lon")) if fallback_data.get("lon") not in (None, "N/A") else None,
                            "timezone": fallback_data.get("timezone", "N/A"),
                            "org": fallback_data.get("org", ip_data["org"]),
                            "isp": fallback_data.get("isp", ip_data["isp"]),
                        })
                        geo_success = True
                        # Removed fallback geolocation message as requested
            except Exception as fallback_error:
                # Both services failed
                ip_data["geo_error"] = f"Primary geolocation service error: {first_error}\nFallback service error: {str(fallback_error)}"
        
        if not geo_success and "geo_error" not in ip_data:
            ip_data["geo_error"] = "All geolocation services failed"
        
        # DNS reverse lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception as e:
            hostname = "No hostname found"
        
        ip_data["hostname"] = hostname
        
        # Add all RDAP data for completeness
        ip_data["rdap_data"] = results
        
        # OS tools section removed for Railway compatibility
        ip_data["os_tools"] = {}
        
        return ip_data
    except Exception as e:
        return {"error": str(e)}

# run_os_command function removed for Railway compatibility

def get_host_info(hostname):
    """Get detailed information about a hostname."""
    try:
        # Prepare the data structure with default values
        host_data = {
            "hostname": hostname,
            "ip_addresses": [],
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "whois_info": {},
            "os_tools": {}
        }
        
        # DNS lookups - get IP addresses
        try:
            ips = socket.getaddrinfo(hostname, None)
            for ip in ips:
                if ip[4][0] not in host_data["ip_addresses"]:
                    host_data["ip_addresses"].append(ip[4][0])
            if not host_data["ip_addresses"]:
                host_data["ip_resolution_error"] = "No IP addresses found for this domain."
        except Exception as e:
            error_msg = str(e)
            if "[Errno 11001] getaddrinfo failed" in error_msg:
                host_data["ip_resolution_error"] = "Domain could not be resolved to an IP address. It may not exist or may be experiencing DNS issues."
            else:
                host_data["ip_resolution_error"] = f"Could not resolve domain: {error_msg}."
            host_data["ip_addresses"] = []
        
        # Get A records
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            for rdata in answers:
                host_data["a_records"].append(str(rdata))
            if not host_data["a_records"]:
                host_data["a_records_error"] = "No A records found for this domain."
        except Exception as e:
            error_msg = str(e)
            if "NXDOMAIN" in error_msg:
                host_data["a_records_error"] = "Domain does not exist (NXDOMAIN)."
            elif "SERVFAIL" in error_msg:
                host_data["a_records_error"] = "DNS server failed to respond properly."
            else:
                host_data["a_records_error"] = "Could not retrieve A records."
            host_data["a_records"] = []
        
        # Get MX records
        try:
            answers = dns.resolver.resolve(hostname, 'MX')
            for rdata in answers:
                # Skip or handle specially if the exchange is just a dot
                if str(rdata.exchange) == '.':
                    host_data["mx_records_error"] = "This domain is configured to not accept emails (null MX record)."
                else:
                    host_data["mx_records"].append(f"{rdata.exchange} (preference: {rdata.preference})")
            if not host_data["mx_records"] and "mx_records_error" not in host_data:
                host_data["mx_records_error"] = "No MX records found for this domain."
        except Exception as e:
            error_msg = str(e)
            if "NXDOMAIN" in error_msg:
                host_data["mx_records_error"] = "Domain does not exist (NXDOMAIN)."
            elif "SERVFAIL" in error_msg:
                host_data["mx_records_error"] = "DNS server failed to respond properly."
            else:
                host_data["mx_records_error"] = "No mail servers configured for this domain."
            host_data["mx_records"] = []
        
        # Get NS records
        try:
            answers = dns.resolver.resolve(hostname, 'NS')
            for rdata in answers:
                # Remove trailing dot from NS records for consistency
                ns_record = str(rdata)
                if ns_record.endswith('.'):
                    ns_record = ns_record[:-1]
                host_data["ns_records"].append(ns_record)
        except Exception as e:
            host_data["ns_records"] = [f"Error resolving NS records: {str(e)}"]
        
        # Get TXT records
        try:
            answers = dns.resolver.resolve(hostname, 'TXT')
            for rdata in answers:
                host_data["txt_records"].append(str(rdata))
        except Exception as e:
            host_data["txt_records"] = [f"Error resolving TXT records: {str(e)}"]
        
        # Get WHOIS information
        try:
            w = whois.whois(hostname)
            # Check if whois returned any meaningful data
            if not w or (hasattr(w, 'status') and w.status is None and hasattr(w, 'domain_name') and w.domain_name is None):
                host_data["whois_info"] = {"error": "No WHOIS data found. This domain may not be registered."}
            else:
                host_data["whois_info"] = w
        except Exception as e:
            error_msg = str(e)
            if "No match for domain" in error_msg or "No whois server" in error_msg:
                host_data["whois_info"] = {"error": "This domain does not appear to be registered."}
            else:
                host_data["whois_info"] = {"error": f"Could not retrieve WHOIS information: {error_msg}"}
        
        # If we have a valid IP, get IP info for the first IP
        valid_ips = [ip for ip in host_data["ip_addresses"] if isinstance(ip, str) and is_valid_ip(ip)]
        if valid_ips:
            try:
                host_data["ip_info"] = get_ip_info(valid_ips[0])
            except Exception as e:
                host_data["ip_info"] = {"error": f"Error getting IP info: {str(e)}"}
        
        # OS tools section removed for Railway compatibility
        host_data["os_tools"] = {}
        
        return host_data
    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    # Usando uma abordagem alternativa que deve funcionar no Railway
    # Baseado na memória de que o Railway usa um ambiente containerizado
    # que pode ter restrições específicas
    return render_template('about.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# Rota alternativa para a página about usando o padrão de URL que sabemos funcionar
@app.route('/lookup/about')
def about_alt():
    return render_template('about.html')

@app.route('/sitemap.xml')
def sitemap():
    sitemap_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://ipsherlock.com/</loc>
    <lastmod>2025-04-24</lastmod>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://ipsherlock.com/about</loc>
    <lastmod>2025-04-24</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://ipsherlock.com/privacy</loc>
    <lastmod>2025-04-24</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>'''
    response = Response(sitemap_xml, mimetype='application/xml')
    return response

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt')

@app.route('/lookup', methods=['POST'])
def lookup():
    """Process the lookup form and redirect to results."""
    query = request.form.get('query', '').strip()
    
    # If the query is empty, redirect back to the home page
    if not query:
        return redirect(url_for('index'))
    
    # Strip common protocols if present
    query = strip_protocols(query)
    
    # Clean up the query - remove any surrounding brackets which might be present for IPv6
    query = query.strip('[]')
    
    # Store the query in the session
    session['last_query'] = query
    
    # Logging is now handled by the before_request handler
    
    # Special handling for IPv6 addresses
    # IPv6 addresses contain colons which can cause issues in form submission
    if ':' in query:
        # Try to handle potential URL encoding in IPv6 addresses
        if '%3A' in query:
            query = query.replace('%3A', ':')
        
        # If it looks like an IPv6 address, try to validate it directly
        try:
            # This will validate the IPv6 address format
            socket.inet_pton(socket.AF_INET6, query)
            # If it's valid, proceed to results
            return redirect(url_for('results', query=query))
        except (socket.error, ValueError):
            # Not a valid IPv6 address, continue with normal validation
            pass
    
    # Validate the query before proceeding
    if not is_valid_ip(query) and not is_valid_hostname(query):
        return render_template('index.html', error="Please enter a valid IP address (like 8.8.8.8, 2001:4860:4860::8888) or domain name (like example.com).")
    
    return redirect(url_for('results', query=query))

def strip_protocols(url):
    """Strip common protocols from URLs."""
    protocols = ['http://', 'https://', 'ftp://', 'ftps://']
    for protocol in protocols:
        if url.startswith(protocol):
            url = url[len(protocol):]
    
    # Also remove any trailing path or query parameters
    url = url.split('/', 1)[0].split('?', 1)[0]
    
    return url

@app.route('/results')
def results():
    # Get the query parameter
    query = request.args.get('query', '').strip()
    
    if not query:
        return redirect(url_for('index'))
    
    # Determine if the query is an IP address (IPv4 or IPv6) or a hostname
    if is_valid_ip(query):
        data = get_ip_info(query)
        query_type = 'ip'
        # Add IP version to the data for display
        if ':' in query:
            data['ip_version_display'] = 'IPv6'
        else:
            data['ip_version_display'] = 'IPv4'
    elif is_valid_hostname(query):
        data = get_host_info(query)
        query_type = 'hostname'
    else:
        # If not a valid IP or hostname, try to interpret as a hostname
        data = get_host_info(query)
        query_type = 'hostname'

    # Geolocation data is no longer used for map display
    
    return render_template('results.html', query=query, data=data, query_type=query_type)

@app.route('/export/<query_type>/<query>')
def export_csv(query_type, query):
    """Export the lookup results to a CSV file."""
    try:
        # Strip protocols if present
        query = strip_protocols(query)
        
        # Get the data based on query type
        if query_type == 'ip':
            data = get_ip_info(query)
        elif query_type == 'hostname':
            data = get_host_info(query)
        else:
            return redirect(url_for('index'))
        
        # Create a CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header row with timestamp
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow(['IPSherlock Investigation Results', f'Query: {query}', f'Generated: {current_time}'])
        writer.writerow([])  # Empty row for spacing
        
        if query_type == 'ip':
            # Write IP information
            writer.writerow(['IP Information', ''])
            writer.writerow(['IP Address', data.get('ip', 'N/A')])
            writer.writerow(['IP Version', data.get('ip_version_display', 'N/A')])
            writer.writerow(['ASN', data.get('asn', 'N/A')])
            writer.writerow(['ASN Description', data.get('asn_description', 'N/A')])
            writer.writerow(['Network', data.get('network', 'N/A')])
            writer.writerow(['Country', data.get('country', 'N/A')])
            writer.writerow(['Region', data.get('region', 'N/A')])
            writer.writerow(['City', data.get('city', 'N/A')])
            writer.writerow(['Organization', data.get('org', 'N/A')])
            writer.writerow(['ISP', data.get('isp', 'N/A')])
            writer.writerow([])  # Empty row for spacing
            
            # Write reverse DNS
            if 'hostnames' in data and data['hostnames']:
                writer.writerow(['Reverse DNS', ''])
                for hostname in data['hostnames']:
                    writer.writerow(['Hostname', hostname])
                writer.writerow([])  # Empty row for spacing
        
        elif query_type == 'hostname':
            # Write hostname information
            writer.writerow(['Hostname Information', ''])
            writer.writerow(['Hostname', data.get('hostname', 'N/A')])
            writer.writerow([])  # Empty row for spacing
            
            # Write IP addresses
            writer.writerow(['IP Addresses', ''])
            for ip in data.get('ip_addresses', []):
                writer.writerow(['IP', ip])
            writer.writerow([])  # Empty row for spacing
            
            # Write DNS records
            if data.get('a_records'):
                writer.writerow(['A Records', ''])
                for record in data['a_records']:
                    writer.writerow(['Record', record])
                writer.writerow([])  # Empty row for spacing
            
            if data.get('mx_records'):
                writer.writerow(['MX Records', ''])
                for record in data['mx_records']:
                    writer.writerow(['Record', record])
                writer.writerow([])  # Empty row for spacing
            
            if data.get('ns_records'):
                writer.writerow(['NS Records', ''])
                for record in data['ns_records']:
                    writer.writerow(['Record', record])
                writer.writerow([])  # Empty row for spacing
            
            if data.get('txt_records'):
                writer.writerow(['TXT Records', ''])
                for record in data['txt_records']:
                    writer.writerow(['Record', record])
                writer.writerow([])  # Empty row for spacing
            
            # Write WHOIS information
            if 'whois_info' in data and not data['whois_info'].get('error'):
                writer.writerow(['WHOIS Information', ''])
                whois_info = data['whois_info']
                
                # Handle person/registrant
                if whois_info.get('person'):
                    if isinstance(whois_info['person'], list):
                        for person in whois_info['person']:
                            writer.writerow(['Person', person])
                    else:
                        writer.writerow(['Person', whois_info['person']])
                
                # Handle registrant
                if whois_info.get('registrant'):
                    writer.writerow(['Registrant', whois_info['registrant']])
                
                # Handle registrant ID
                if whois_info.get('registrant_id'):
                    writer.writerow(['Registrant ID', whois_info['registrant_id']])
                
                # Handle emails
                if whois_info.get('email'):
                    if isinstance(whois_info['email'], list):
                        for email in whois_info['email']:
                            writer.writerow(['Email', email])
                    else:
                        writer.writerow(['Email', whois_info['email']])
                
                # Handle dates
                if whois_info.get('creation_date'):
                    if isinstance(whois_info['creation_date'], list):
                        writer.writerow(['Creation Date', whois_info['creation_date'][0]])
                    else:
                        writer.writerow(['Creation Date', whois_info['creation_date']])
                
                if whois_info.get('expiration_date'):
                    if isinstance(whois_info['expiration_date'], list):
                        writer.writerow(['Expiration Date', whois_info['expiration_date'][0]])
                    else:
                        writer.writerow(['Expiration Date', whois_info['expiration_date']])
                
                if whois_info.get('updated_date'):
                    if isinstance(whois_info['updated_date'], list):
                        writer.writerow(['Last Updated', whois_info['updated_date'][0]])
                    else:
                        writer.writerow(['Last Updated', whois_info['updated_date']])
        
        # Prepare the response
        output.seek(0)
        filename = f"ipsherlock_{query.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )
    
    except Exception as e:
        # If anything goes wrong, redirect to results page
        return redirect(url_for('results', query=query))

# Route for users to check their own IP address directly from Flask
@app.route('/check-my-ip')
def check_my_ip():
    # Get client IP address directly from Flask's request object
    # First check for X-Forwarded-For header (common in proxies/load balancers)
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, the first one is the client's
        client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    else:
        # If no forwarding header, use the direct remote address
        client_ip = request.remote_addr
    
    # Redirect to results page with the user's IP address
    return redirect(url_for('results', query=client_ip))

# Route to show design options
@app.route('/design-options')
def design_options():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'design_options.html')

# This route will be used to check if the app is running
@app.route('/health')
def health_check():
    return {"status": "ok", "message": "IPSherlock is running"}

# Debug route has been removed for security

# Add admin route to view logs
@app.route('/admin/logs')
def admin_logs():
    # Check if the provided key matches the admin password
    if request.args.get('key') != ADMIN_PASSWORD:
        return "Not Found", 404
    
    # Get logs from file
    log_entries = []
    
    # Try Railway logs first
    if os.environ.get('RAILWAY_ENVIRONMENT'):
        try:
            log_file = os.path.join('/tmp', LOG_FILENAME)
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_entries = [line.strip() for line in f.readlines()]
        except Exception as e:
            log_entries = [f"Error reading Railway logs: {e}"]
    # Try local logs
    else:
        try:
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            log_file = os.path.join(log_dir, 'search.log')
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_entries = [line.strip() for line in f.readlines()]
        except Exception as e:
            log_entries = [f"Error reading local logs: {e}"]
    
    # Reverse to show newest first
    log_entries.reverse()
    
    # Format logs to highlight IPv6 addresses
    formatted_logs = []
    for log in log_entries:
        # Check if the log contains an IPv6 address (has parentheses with IPv6 inside)
        if '(IPv6)' in log:
            # Find the IPv6 address (assuming it's at the beginning of the log)
            ipv6_part = log.split(' (IPv6)')[0]
            rest_of_log = log.split(' (IPv6)')[1]
            # Format with HTML
            formatted_log = f'<span class="ipv6">{ipv6_part} (IPv6)</span>{rest_of_log}'
            formatted_logs.append(formatted_log)
        else:
            formatted_logs.append(log)
    
    # Check if access log file exists
    access_log_exists = False
    
    if os.environ.get('RAILWAY_ENVIRONMENT'):
        access_log_file = os.path.join('/tmp', ACCESS_LOG_FILENAME)
        access_log_exists = os.path.exists(access_log_file)
    else:
        access_log_file = os.path.join(log_dir, 'access.log')
        access_log_exists = os.path.exists(access_log_file)
    
    return render_template('admin_logs.html', logs=formatted_logs, access_log_exists=access_log_exists)

# Script logs route has been removed

# Add route to download access logs - with additional security measures
@app.route('/admin/download-access-logs')
def download_access_logs():
    # Check if the provided key matches the admin password
    if request.args.get('key') != ADMIN_PASSWORD:
        return "Not Found", 404
    
    # Additional security: Check referer to prevent direct access
    referer = request.headers.get('Referer', '')
    if not referer or '/admin/logs' not in referer:
        # Log potential unauthorized access attempt
        print(f"Warning: Unauthorized access attempt to logs from {request.remote_addr}")
        return "Not Found", 404
    
    # Generate a timestamped filename for the log
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    download_filename = f"ipsherlock_access_log_{timestamp}.log"
    
    # Determine the log file path based on environment
    if os.environ.get('RAILWAY_ENVIRONMENT'):
        access_log_file = os.path.join('/tmp', ACCESS_LOG_FILENAME)
        
        # If the file doesn't exist yet, create an empty one
        if not os.path.exists(access_log_file):
            with open(access_log_file, 'w', encoding='utf-8') as f:
                f.write(f"# Access log file created on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    else:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        access_log_file = os.path.join(log_dir, 'access.log')
        
        # If the file doesn't exist yet, create an empty one
        if not os.path.exists(access_log_file):
            os.makedirs(log_dir, exist_ok=True)
            with open(access_log_file, 'w', encoding='utf-8') as f:
                f.write(f"# Access log file created on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Log this download event to console
    print(f"Access log file downloaded at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Send the file as an attachment
    return send_file(access_log_file, 
                    as_attachment=True,
                    download_name=download_filename,
                    mimetype='text/plain')

if __name__ == '__main__':
    # Add .gitignore entry for logs directory if it doesn't exist
    gitignore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.gitignore')
    if os.path.exists(gitignore_path):
        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read()
        if 'logs/' not in gitignore_content:
            with open(gitignore_path, 'a') as f:
                f.write('\n# Ignore logs directory\nlogs/\n')
    else:
        with open(gitignore_path, 'w') as f:
            f.write('# Ignore logs directory\nlogs/\n')
    
    # Create a robots.txt file to prevent indexing of admin routes
    robots_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'robots.txt')
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'), exist_ok=True)
    if not os.path.exists(robots_path):
        try:
            with open(robots_path, 'w') as f:
                f.write("User-agent: *\n")
                f.write("Disallow: /admin/\n")
        except Exception as e:
            print(f"Could not create robots.txt file: {e}")
    
    # Use Railway's PORT environment variable if available, otherwise default to 5000
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
