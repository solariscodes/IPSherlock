#!/usr/bin/env python
"""
Domain Availability Checker
---------------------------
This script checks the availability of domain names from a list.
It uses multiple methods to verify availability:
1. WHOIS lookup
2. DNS resolution
"""

import whois
import socket
import dns.resolver
import time
import csv
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# TLDs to check for each domain name
DEFAULT_TLDS = ['.com', '.net', '.org', '.io', '.app', '.dev']

def check_domain_whois(domain):
    """
    Check domain availability using WHOIS lookup.
    Returns True if domain appears to be available, False otherwise.
    """
    try:
        w = whois.whois(domain)
        # If no creation date or registrar, domain might be available
        if w.domain_name is None or w.registrar is None:
            return True
        return False
    except Exception as e:
        # If WHOIS query fails with a specific error indicating no match, domain might be available
        if "No match for domain" in str(e) or "No entries found" in str(e):
            return True
        # For other errors, we can't determine availability
        return None

def check_domain_dns(domain):
    """
    Check domain availability using DNS resolution.
    Returns True if domain appears to be available, False otherwise.
    """
    try:
        # Try to resolve the domain's A record
        dns.resolver.resolve(domain, 'A')
        # If resolution succeeds, domain is registered and has DNS records
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # NXDOMAIN means the domain doesn't exist in DNS, suggesting it's available
        return True
    except Exception:
        # For other errors, we can't determine availability
        return None

def check_domain_socket(domain):
    """
    Check domain availability using socket resolution.
    Returns True if domain appears to be available, False otherwise.
    """
    try:
        # Try to get IP address for the domain
        socket.gethostbyname(domain)
        # If resolution succeeds, domain is registered and has DNS records
        return False
    except socket.gaierror:
        # If resolution fails, domain might be available
        return True
    except Exception:
        # For other errors, we can't determine availability
        return None

def check_domain(domain):
    """
    Check domain availability using multiple methods.
    Returns a tuple of (domain, is_available, confidence, methods_used).
    """
    results = {}
    methods_used = []
    
    # Check using WHOIS
    whois_result = check_domain_whois(domain)
    if whois_result is not None:
        results['whois'] = whois_result
        methods_used.append('whois')
    
    # Check using DNS
    dns_result = check_domain_dns(domain)
    if dns_result is not None:
        results['dns'] = dns_result
        methods_used.append('dns')
    
    # Check using socket
    socket_result = check_domain_socket(domain)
    if socket_result is not None:
        results['socket'] = socket_result
        methods_used.append('socket')
    
    # Calculate availability and confidence
    if not results:
        return domain, None, 0, []
    
    # Count available results
    available_count = sum(1 for result in results.values() if result)
    total_count = len(results)
    
    # Calculate confidence percentage
    confidence = (available_count / total_count) * 100 if total_count > 0 else 0
    
    # Domain is considered available if more than 50% of methods indicate it's available
    is_available = confidence >= 50
    
    return domain, is_available, confidence, methods_used

def process_domain_list(base_names, tlds=DEFAULT_TLDS, max_workers=10):
    """
    Process a list of domain base names, checking availability for each with different TLDs.
    Returns a list of results.
    """
    domains_to_check = []
    
    # Generate full domain names with TLDs
    for base_name in base_names:
        base_name = base_name.lower().strip()
        # Skip empty names
        if not base_name:
            continue
        # Remove any existing TLD if present
        if '.' in base_name:
            parts = base_name.split('.')
            if len(parts[-1]) >= 2 and len(parts[-1]) <= 4:  # Simple TLD check
                base_name = '.'.join(parts[:-1])
        
        # Add each TLD to the base name
        for tld in tlds:
            domains_to_check.append(f"{base_name}{tld}")
    
    results = []
    
    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains_to_check}
        
        # Process results as they complete with a progress bar
        with tqdm(total=len(future_to_domain), desc="Checking domains") as pbar:
            for future in as_completed(future_to_domain):
                domain, is_available, confidence, methods_used = future.result()
                results.append({
                    'domain': domain,
                    'available': is_available,
                    'confidence': confidence,
                    'methods': ', '.join(methods_used)
                })
                pbar.update(1)
    
    # Sort results by availability (available domains first) and then by domain name
    results.sort(key=lambda x: (0 if x['available'] else 1, x['domain']))
    
    return results

def save_results_to_csv(results, output_file):
    """Save domain availability results to a CSV file."""
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['domain', 'available', 'confidence', 'methods']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            writer.writerow(result)

def print_results(results):
    """Print domain availability results to the console."""
    available_domains = [r for r in results if r['available']]
    unavailable_domains = [r for r in results if not r['available']]
    
    print("\n===== AVAILABLE DOMAINS =====")
    if available_domains:
        for result in available_domains:
            print(f"{result['domain']} - Confidence: {result['confidence']:.1f}% - Methods: {result['methods']}")
    else:
        print("No available domains found.")
    
    print("\n===== UNAVAILABLE DOMAINS =====")
    if unavailable_domains:
        for result in unavailable_domains:
            print(f"{result['domain']} - Confidence: {result['confidence']:.1f}% - Methods: {result['methods']}")
    else:
        print("No unavailable domains found.")

def main():
    parser = argparse.ArgumentParser(description='Check domain name availability.')
    parser.add_argument('--input', '-i', help='Input file with domain names (one per line)')
    parser.add_argument('--output', '-o', help='Output CSV file for results')
    parser.add_argument('--tlds', '-t', help='Comma-separated list of TLDs to check (default: .com,.net,.org,.io,.app,.dev)')
    parser.add_argument('--domains', '-d', nargs='+', help='List of domain base names to check')
    parser.add_argument('--workers', '-w', type=int, default=10, help='Number of worker threads (default: 10)')
    
    args = parser.parse_args()
    
    # Get domain names from input file or command line arguments
    base_names = []
    if args.input:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                base_names = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            return 1
    elif args.domains:
        base_names = args.domains
    else:
        print("Please provide domain names using --input or --domains", file=sys.stderr)
        return 1
    
    # Get TLDs to check
    tlds = DEFAULT_TLDS
    if args.tlds:
        tlds = [tld.strip() for tld in args.tlds.split(',')]
        # Ensure TLDs start with a dot
        tlds = [tld if tld.startswith('.') else f'.{tld}' for tld in tlds]
    
    print(f"Checking {len(base_names)} base names with {len(tlds)} TLDs...")
    
    # Process domains
    results = process_domain_list(base_names, tlds, args.workers)
    
    # Save results to CSV if output file is specified
    if args.output:
        save_results_to_csv(results, args.output)
        print(f"Results saved to {args.output}")
    
    # Print results to console
    print_results(results)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
