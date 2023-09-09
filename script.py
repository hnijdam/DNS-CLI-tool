import dns.resolver
import socket
import sys
import ssl
import subprocess
import OpenSSL.crypto
from datetime import datetime
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
    print(f"\033[1;46;5m{header_text}\033[0m")  # Aangepaste lettergrootte
    print_border("=")

def print_border(border_char):
    border_line = border_char * 80
    print(border_line)

blauw_vet = '\033[1;34m'
geel_vet = '\033[1;33m'
einde_opmaak = '\033[0m'

def omgekeerd_opzoeken(ip_adres):
    try:
        output = subprocess.check_output(["host", ip_adres]).decode('utf-8')
        lines = output.splitlines()
        ptr_record = lines[-1].split()[-1]
        return ptr_record
    except subprocess.CalledProcessError:
        return None

def query_a_records(a_records, record_type):
    if len(a_records) > 0:
        print_section_header(f"{geel_vet}Omgekeerd Opzoeken ({record_type} Records):{einde_opmaak}")
        for record in a_records:
            ip_adres = record.address
            hostname = omgekeerd_opzoeken(ip_adres)
            if hostname:
                print(f"{ip_adres} -> {hostname}")
            else:
                print(f"{ip_adres} -> Niet gevonden")
    else:
        print_section_header(f"{geel_vet}Geen {record_type} Records gevonden.{einde_opmaak}")

def query_www_subdomain(subdomein, record_type):
    try:
        records = resolver.resolve(subdomein, record_type)
        if records:
            query_a_records(records, record_type)
        else:
            print_section_header(f"{geel_vet}Geen {record_type} Records gevonden voor {subdomein}.{einde_opmaak}")
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen {record_type} Records gevonden voor {subdomein}.{einde_opmaak}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{geel_vet}Geen {record_type} Records gevonden voor {subdomein}.{einde_opmaak}")

def query_domain_info(domein_naam):
    resolver = dns.resolver.Resolver()
    
    print_large_ascii_text(f"{blauw_vet}Opvragen van informatie voor domein: {domein_naam}{einde_opmaak}\n")

    try:
        a_records = resolver.resolve(domein_naam, 'A')
        query_a_records(a_records, 'A')

    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen A Records gevonden voor {domein_naam}.{einde_opmaak}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{geel_vet}Geen A Records gevonden voor {domein_naam}.{einde_opmaak}")

    # AAAA Records voor hoofddomein
    try:
        aaaa_records = resolver.resolve(domein_naam, 'AAAA')
        query_a_records(aaaa_records, 'AAAA')

    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen AAAA Records gevonden voor {domein_naam}.{einde_opmaak}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{geel_vet}Geen AAAA Records gevonden voor {domein_naam}.{einde_opmaak}")

    # A Records voor www subdomein
    try:
        query_a_records(resolver.resolve(f'www.{domein_naam}', 'A'), 'A')
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen A Records gevonden voor www.{domein_naam}.{einde_opmaak}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{geel_vet}Geen A Records gevonden voor www.{domein_naam}.{einde_opmaak}")

    # AAAA Records voor www subdomein
    try:
        query_a_records(resolver.resolve(f'www.{domein_naam}', 'AAAA'), 'AAAA')
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen AAAA Records gevonden voor www.{domein_naam}.{einde_opmaak}")
    except dns.resolver.NoAnswer:
        print_section_header(f"{geel_vet}Geen AAAA Records gevonden voor www.{domein_naam}.{einde_opmaak}")

    # Nameservers
    try:
        answers = resolver.resolve(domein_naam, 'NS')
        print_section_header(f"{geel_vet}Nameservers:{einde_opmaak}")
        for answer in answers:
            print(answer)
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen Nameservers gevonden.{einde_opmaak}")

    # MX Records
    try:
        answers = resolver.resolve(domein_naam, 'MX')
        print_section_header(f"{geel_vet}MX Records:{einde_opmaak}")
        for answer in answers:
            print(f"Priority: {answer.preference}, Mailserver: {answer.exchange}")
    except dns.resolver.NXDOMAIN:
        print_section_header(f"{geel_vet}Geen MX Records gevonden.{einde_opmaak}")

    # SSL-certificaatgegevens
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domein_naam, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domein_naam) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                issuer = x509.get_issuer().CN
                valid_from = datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
                valid_until = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                print_section_header(f"{geel_vet}SSL-certificaatgegevens:{einde_opmaak}")
                print(f"hostnaam: {x509.get_subject().CN}")
                print(f"Issuer: {issuer}")
                print(f"Geldig vanaf: {valid_from.strftime('%Y-%m-%d')}")
                print(f"Geldig tot: {valid_until.strftime('%Y-%m-%d')}")
    except (ssl.SSLError, ConnectionError):
        print_section_header(f"{geel_vet}SSL-certificaatgegevens niet beschikbaar.{einde_opmaak}")
    except socket.gaierror:
        print_section_header(f"{geel_vet}SSL-certificaatgegevens niet beschikbaar.{einde_opmaak}")
        print("Heb je een typefout gemaakt?")  # Vriendelijke boodschap voor de fout

    # SPF Records
    try:
        answers = resolver.resolve('_spf.' + domein_naam, 'TXT')
        print_section_header(f"{geel_vet}SPF Records:{einde_opmaak}")
        for answer in answers:
            spf_record = answer.to_text()
            info_lines = [line for line in spf_record.split("\n") if line.strip()]
            max_line_length = 76 - 4  # Aangepast om rekening te houden met de "| " en " |" tekens
            for line in info_lines:
                for i in range(0, len(line), max_line_length):
                    print(f"\033[0m{line[i:i+max_line_length]:<76}\033[0m")  # Opmaak hier resetten naar normaal
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print_section_header(f"{geel_vet}Geen SPF Records gevonden.{einde_opmaak}")

    # DMARC Records
    try:
        answers = resolver.resolve('_dmarc.' + domein_naam, 'TXT')
        dmarc_info = ""  # Initialiseer de dmarc_info variabele
        for answer in answers:
            dmarc_info += answer.to_text()
        print_section_header(f"{geel_vet}DMARC Records:{einde_opmaak}")
        info_lines = [line for line in dmarc_info.split("\n") if line.strip()]
        max_line_length = 76 - 4  # Aangepast om rekening te houden met de "| " en " |" tekens
        for line in info_lines:
            for i in range(0, len(line), max_line_length):
                print(f"\033[0m{line[i:i+max_line_length]:<76}\033[0m")  # Opmaak hier resetten naar normaal
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print_section_header(f"{geel_vet}Geen DMARC Records gevonden.{einde_opmaak}")
        print("Heb je een typefout gemaakt?")  # Vriendelijke boodschap voor de fout

    # DKIM Records
    try:
        answers = resolver.resolve('default._domainkey.' + domein_naam, 'TXT')
        dkim_info = "\n"  # Initialiseer de dkim_info variabele
        for answer in answers:
            dkim_info += answer.to_text()
        print_section_header(f"{geel_vet}DKIM Records:{einde_opmaak}")
        info_lines = [line for line in dkim_info.split("\n") if line.strip()]
        max_line_length = 76  # Aangepast om rekening te houden met de "| " en " |" tekens
        for line in info_lines:
            for i in range(0, len(line), max_line_length):
                print(f"\033[1;37m{line[i:i+max_line_length]:<76}\033[0m")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print_section_header(f"{geel_vet}Geen DKIM Records gevonden.{einde_opmaak}")

print()  # Voeg een spatie toe na de laatste uitvoer

if len(sys.argv) == 1:
    domein_om_op_te_vragen = input("Voer het domein in waarvoor je informatie wilt opvragen: ")
else:
    domein_om_op_te_vragen = sys.argv[1]

query_domain_info(domein_om_op_te_vragen)


print("\n" * 3)  # Adjust the number of blank lines as needed


print("Einde")
