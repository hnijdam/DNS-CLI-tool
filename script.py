import dns.resolver
import socket
import ssl
import OpenSSL.crypto
import subprocess
from datetime import datetime
import sys
import dns.exception

def print_large_ascii_text(text):
    ascii_text = """
  _   _                   _           _                      _         _        __       
 | | | |_   _  __ _  ___ ( )___    __| | ___  _ __ ___   ___(_)_ __   (_)_ __  / _| ___  
 | |_| | | | |/ _` |/ _ \|// __|  / _` |/ _ \| '_ ` _ \ / _ \ | '_ \  | | '_ \| |_ / _ \ 
 |  _  | |_| | (_| | (_) | \__ \ | (_| | (_) | | | | | |  __/ | | | | | | | | |  _| (_) |
 |_| |_|\__,_|\__, |\___/  |___/  \__,_|\___/|_| |_| |_|\___|_|_| |_| |_|_| |_|_|  \___/ 
              |___/                                                                      
    """

    print(ascii_text)

def print_section_header(header_text):
    print_border("=")
    print(f"\033[1;46;5m{header_text}\033[0m")  # Adjusted font size
    print_border("=")

def print_border(border_char):
    border_line = border_char * 80
    print(border_line)

blue_bold = '\033[1;34m'
yellow_bold = '\033[1;33m'
end_format = '\033[0m'

def reverse_lookup(ip_address):
    try:
        output = subprocess.check_output(["host", ip_address]).decode('utf-8')
        lines = output.splitlines()
        ptr_record = lines[-1].split()[-1]
        return ptr_record
    except subprocess.CalledProcessError:
        return None

def query_a_records(a_records, record_type):
    if len(a_records) > 0:
        print_section_header(f"{yellow_bold}Reverse Lookup ({record_type} Records):{end_format}")
        for record in a_records:
            ip_address = record.address
            hostname = reverse_lookup(ip_address)
            if hostname:
                print(f"{ip_address} -> {hostname}")
            else:
                print(f"{ip_address} -> Not found")
    else:
        print_section_header(f"{yellow_bold}No {record_type} Records found.{end_format}")

def query_www_subdomain(subdomain, record_type):
    try:
        records = resolver.resolve(subdomain, record_type)
        if records:
            query_a_records(records, record_type)
        else:
            print_section_header(f"{yellow_bold}No {record_type} Records found for {subdomain}.{end_format}")
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No {record_type} Records found for {subdomain}.{end_format}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{yellow_bold}No {record_type} Records found for {subdomain}.{end_format}")

def query_domain_info(domain_name):
    resolver = dns.resolver.Resolver()
    
    print_large_ascii_text(f"{blue_bold}Querying information for domain: {domain_name}{end_format}\n")

    try:
        a_records = resolver.resolve(domain_name, 'A')
        query_a_records(a_records, 'A')

    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No A Records found for {domain_name}.{end_format}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{yellow_bold}No A Records found for {domain_name}.{end_format}")

    # AAAA Records for main domain
    try:
        aaaa_records = resolver.resolve(domain_name, 'AAAA')
        query_a_records(aaaa_records, 'AAAA')

    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No AAAA Records found for {domain_name}.{end_format}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{yellow_bold}No AAAA Records found for {domain_name}.{end_format}")

    # A Records for www subdomain
    try:
        query_a_records(resolver.resolve(f'www.{domain_name}', 'A'), 'A')
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No A Records found for www.{domain_name}.{end_format}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{yellow_bold}No A Records found for www.{domain_name}.{end_format}")

    # AAAA Records for www subdomain
    try:
        query_a_records(resolver.resolve(f'www.{domain_name}', 'AAAA'), 'AAAA')
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No AAAA Records found for www.{domain_name}.{end_format}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{yellow_bold}No AAAA Records found for www.{domain_name}.{end_format}")

    # Nameservers
    try:
        answers = resolver.resolve(domain_name, 'NS')
        print_section_header(f"{yellow_bold}Nameservers:{end_format}")
        for answer in answers:
            print(answer)
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No Nameservers found.{end_format}")

    # MX Records
    try:
        answers = resolver.resolve(domain_name, 'MX')
        print_section_header(f"{yellow_bold}MX Records:{end_format}")
        for answer in answers:
            print(f"Preference: {answer.preference}, Mail Server: {answer.exchange}")
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{yellow_bold}No MX Records found.{end_format}")

    # SSL Certificate Details
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain_name, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                issuer = x509.get_issuer().CN
                valid_from = datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
                valid_until = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                print_section_header(f"{yellow_bold}SSL Certificate Details:{end_format}")
                print(f"Subject: {x509.get_subject().CN}")
                print(f"Issuer: {issuer}")
                print(f"Valid From: {valid_from.strftime('%Y-%m-%d')}")
                print(f"Valid Until: {valid_until.strftime('%Y-%m-%d')}")
    except (ssl.SSLError, ConnectionError):
        print_section_header(f"{yellow_bold}SSL Certificate details not available.{end_format}")
    except socket.gaierror:
        print_section_header(f"{yellow_bold}SSL Certificate details not available.{end_format}")
        print("Did you make a typo?")  # Friendly message for the error

    # SPF Records
    try:
        answers = resolver.resolve('_spf.' + domain_name, 'TXT')
        print_section_header(f"{yellow_bold}SPF Records:{end_format}")
        for answer in answers:
            spf_record = answer.to_text()
            info_lines = [line for line in spf_record.split("\n") if line.strip()]
            max_line_length = 76 - 4  # Adjusted to account for the "| " and " |" characters
            for line in info_lines:
                for i in range(0, len(line), max_line_length):
                    print(f"\033[0m{line[i:i+max_line_length]:<76}\033[0m")  # Reset formatting to normal here
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print_section_header(f"{yellow_bold}No SPF Records found.{end_format}")

    # DMARC Records
    try:
        answers = resolver.resolve('_dmarc.' + domain_name, 'TXT')
        dmarc_info = ""  # Initialize the dmarc_info variable
        for answer in answers:
            dmarc_info += answer.to_text()
        print_section_header(f"{yellow_bold}DMARC Records:{end_format}")
        info_lines = [line for line in dmarc_info.split("\n") if line.strip()]
        max_line_length = 76 - 4  # Adjusted to account for the "| " and " |" characters
        for line in info_lines:
            for i in range(0, len(line), max_line_length):
                print(f"\033[0m{line[i:i+max_line_length]:<76}\033[0m")  # Reset formatting to normal here
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print_section_header(f"{yellow_bold}No DMARC Records found.{end_format}")
        print("Did you make a typo?")  # Friendly message for the error

    # DKIM Records
    try:
        answers = resolver.resolve('default._domainkey.' + domain_name, 'TXT')
        dkim_info = "\n"  # Initialize the dkim_info variable
        for answer in answers:
            dkim_info += answer.to_text()
        print_section_header(f"{yellow_bold}DKIM Records:{end_format}")
        info_lines = [line for line in dkim_info.split("\n") if line.strip()]
        max_line_length = 76  # Adjusted to account for the "| " and " |" characters
        for line in info_lines:
            for i in range(0, len(line), max_line_length):
                print(f"\033[1;37m{line[i:i+max_line_length]:<76}\033[0m")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print_section_header(f"{yellow_bold}No DKIM Records found.{end_format}")
    #    print("Did you make a typo?")  # Friendly message for the error

    print()  # Add a space after the last output

if len(sys.argv) == 1:
    domain_to_query = input("Enter the domain you want to query: ")
else:
    domain_to_query = sys.argv[1]

query_domain_info(domain_to_query)

print("Script completed.")
