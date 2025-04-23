from flask import Flask, render_template, request, redirect, url_for, Response, session
import socket
import whois
import dns.resolver
import requests
import re
# subprocess and shlex imports removed for Railway compatibility
from ipwhois import IPWhois
import csv
import io
import json
import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = 'ipsherlock_detective_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

# Define constants for log storage
LOG_FILENAME = 'railway_logs.txt'
MAX_LOGS = 1000  # Maximum number of logs to store

# Setup logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

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

# Log all requests to the results page
@app.before_request
def log_request():
    if request.path == '/results' and 'query' in request.args:
        query = request.args.get('query', '').strip()
        if query:
            # Get client IP, handling proxy headers
            if request.headers.get('X-Forwarded-For'):
                client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            else:
                client_ip = request.remote_addr
            
            # Create log entry in same format
            timestamp = datetime.now().strftime('[%d/%b/%Y %H:%M:%S]')
            log_entry = f"{client_ip} - - {timestamp} \"GET /results?query={query} HTTP/1.1\" 200 -"
            
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

def is_valid_ip(ip):
    """Check if the input is a valid IP address."""
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        return False
    # Check that each octet is between 0 and 255
    octets = ip.split('.')
    for octet in octets:
        if int(octet) < 0 or int(octet) > 255:
            return False
    return True

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
    """Get detailed information about an IP address."""
    try:
        # Basic IP info
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        
        # Prepare the data with basic info
        ip_data = {
            "ip": ip,
            "asn": results.get("asn", "N/A"),
            "asn_description": results.get("asn_description", "N/A"),
            "network": results.get("network", {}).get("cidr", "N/A"),
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "postal": "N/A",
            "latitude": "N/A",
            "longitude": "N/A",
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
                    "latitude": geo_data.get("latitude", "N/A"),
                    "longitude": geo_data.get("longitude", "N/A"),
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
                            "latitude": fallback_data.get("lat", "N/A"),
                            "longitude": fallback_data.get("lon", "N/A"),
                            "timezone": fallback_data.get("timezone", "N/A"),
                            "org": fallback_data.get("org", ip_data["org"]),
                            "isp": fallback_data.get("isp", ip_data["isp"]),
                        })
                        geo_success = True
                        ip_data["geo_note"] = "Using fallback geolocation service (ip-api.com)"
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
    """Render the home page with the search form."""
    return render_template('index.html')

@app.route('/lookup', methods=['POST'])
def lookup():
    """Process the lookup form and redirect to results."""
    query = request.form.get('query', '').strip()
    
    # If the query is empty, redirect back to the home page
    if not query:
        return redirect(url_for('index'))
    
    # Strip common protocols if present
    query = strip_protocols(query)
    
    # Store the query in the session
    session['last_query'] = query
    
    # Logging is now handled by the before_request handler
    
    # Validate the query before proceeding
    if not is_valid_ip(query) and not is_valid_hostname(query):
        return render_template('index.html', error="Please enter a valid IP address or domain name.")
    
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
    """Show the results of the lookup."""
    query = request.args.get('query', '').strip()
    if not query:
        return redirect(url_for('index'))
    
    # Strip common protocols if present
    query = strip_protocols(query)
    
    # Logging is now handled by the before_request handler
    
    # Determine if the query is an IP address or hostname
    try:
        if is_valid_ip(query):
            data = get_ip_info(query)
            query_type = 'ip'
        elif is_valid_hostname(query):
            data = get_host_info(query)
            query_type = 'hostname'
        else:
            data = {"error": "Invalid input. Please enter a valid IP address or hostname."}
            query_type = 'invalid'
    except Exception as e:
        data = {"error": f"An error occurred during lookup: {str(e)}"}
        query_type = 'error'
    
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

# This route will be used to check if the app is running
@app.route('/health')
def health_check():
    return {"status": "ok", "message": "IPSherlock is running"}

# Add admin route to view logs
@app.route('/admin/logs')
def admin_logs():
    # Simple authentication - you can enhance this later
    if request.args.get('key') != app.secret_key:
        return "Unauthorized", 401
    
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
    
    return render_template('admin_logs.html', logs=log_entries)

if __name__ == '__main__':
    # Add .gitignore entry for logs directory if it doesn't exist
    gitignore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.gitignore')
    if os.path.exists(gitignore_path):
        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read()
        if 'logs/' not in gitignore_content:
            with open(gitignore_path, 'a') as f:
                f.write('\n# Log files\nlogs/\n')
    else:
        with open(gitignore_path, 'w') as f:
            f.write('# Log files\nlogs/\n')
    
    # Database tables are created at app startup
    
    # Use Railway's PORT environment variable if available, otherwise default to 5000
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
