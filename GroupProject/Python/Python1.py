import socket  #Provides access to the BSD socket interface
import sys     #Provides access to some variables used or maintained by the python interpreter
import json    #Provides functions for encoding and decoding JSON data

from argparse import ArgumentParser, SUPPRESS  #Provides functions for parsing command-line arguments
from datetime import datetime                  #Provides classes for manipulating dates and times
from time import sleep                         #Provides functions for suspending execution of a script for a given number of seconds
from csv import DictWriter                     #Implements classes to read and write tabular data in CSV format

try:
    from OpenSSL import SSL         #If any of the required modules('OpenSSL' and 'json2html') fail to import, it prints a message asking to 
    from json2html import *          #install the required modules and exits the script with a non-zero exit code
except ImportError:
    print('Please install required modules: pip install')
    sys.exit(1)

######## Colour of Text ########

class Clr:                  #Formatting text with colours for output in a terminal or command prompt
    RST = '\033[39m'        #Resets the colour to the default terminal colour
    RED = '\033[31m'        #ANSI Escape Codes: A sequence of characters that control the formatting, colour, etc.
    GREEN = '\033[32m'      #'\033' is the escape character followed by '[' which is the Control Sequence Introductor(CSI) for ANSI Escape Codes
    YELLOW = '\033[33m'     #The numbers after the '[' determines the colour or formatting. 

######## SSL connect to hosts + retrieve SSL certs ########

class SSLChecker:          #This class provides functionality to establish SSL connections to hosts and retrieve their SSL certs 
    total_valid = 0        #These are class-level variables initialized with integer values
    total_expired = 0      #Used for counting the number of certificates with different statuses
    total_failed = 0
    total_warning = 0

    def get_cert(self, host, port, socks_host=None, socks_port=None):    #Establish a connection to a specified host + retrieve its SSL Cert
        if socks_host:                                                   #['socks_host + port'] are optional parameters for specifying a SOCKS proxy server
            import socks                                                 

            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(socks_port), True)  #Configures the socket to use the SOCKS proxy
            socket.socket = socks.socksocket                                                   

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    #Creates a TCP socket('.socket') using IPv4('AF_INET') and TCP protocols('SOCK_STREAM')
        osobj = SSL.Context(SSL.TLSv1_2_METHOD)                     #Sets up an OpenSSL context object('osobj') using TLSv1.2 method
        sock.connect((host, int(port)))                             #Establishes a connection to the target host and port
        oscon = SSL.Connection(osobj, sock)                         #Creates an SSL connection object('oscon') using the OpenSSL context and the socket
        oscon.set_tlsext_host_name(host.encode())                   #Sets the TLS extension hostname to the target host
        oscon.set_connect_state()                                   #Sets the connection state to connect
        oscon.do_handshake()                                        #Performs the SSL handshake
        cert = oscon.get_peer_certificate()                         #Retrieves the peer certificate of the server
        resolved_ip = socket.gethostbyname(host)                    #Resolves the IP address of the host
        sock.close()                                                #Closes the socket connection

        return cert, resolved_ip                                    #Returns the SSL cert and the resolved IP address of the host

    def border_msg(self, message):                        #Method used to print a message inside a border box
        row = len(message)                                #Calculates the length of the message to determine the width of the border
        h = ''.join(['+'] + ['-' * row] + ['+'])          #Constructs the horizontal border line using '[+]' characters at the beginning + end | '[-]' in between
        result = h + '\n' "|" + message + "|"'\n' + h     #Joins the border line with the message enclosed within vertical bars '|'
        print(result) 

    def analyze_ssl(self, host, context, user_args):   #Method used to analyze the security of the SSL certificate of a given host 
        try:
            from urllib.request import urlopen         #Imports 'urlopen' from the appropriate module ('urllib.request' or 'urllib2') based on the python version
            except ImportError
            from urllib2 import urlopen

        api_url = 'https://api.ssllabs.com/api/v3'                                            #Specifies the url of the SSL Labs API
        while True:                                                                           #Initiates an infinite loop, code will execute until 'break' statement
            if user_args.verbose:                                                             #Enters a loop to repeatedly request an analysis of the SSL certificate
                print('{}Requesting analyze to {}{}\n'.format(Clr.YELLOW, api_url, Clr.RST))   #until the analysis is complete

            main_request = json.loads(urlopen(api_url + 'analyze?host={}'.format(host)).read().decode('utf-8'))    #Sends a request to the SSL Labs API to analyze the SSL Cert of the specified host
            if main_request['status'] in ('DNS', 'IN_PROGRESS'):                                                   #Checks if the status is still ongoing or waiting for DNS resolution
                if user_args.verbose:
                    print('{}Analyze waiting for reports to be finished (5 secs){}\n'.format(Clr.YELLOW, Clr.RST))

                sleep(5)     #Pauses the execution of the loop for 5 seconds
                continue     #Causes the loop to skip the rest of the code block and start the next iteration immediately

            elif main_request['status'] == 'READY':                              #Checks if the analysis status is 'READY', meaning the analysis is complete
                if user_args.verbose:                                            #Checks if verbose output is enabled based on the 'user_args' parameter
                    print('{}Analyze is ready{}\n'.format(Clr.YELLOW, Clr.RST))
                                                                                 #Overall, this loop continuously requests an SSL cert analysis from the SSL Labs API until compete analysis, with optional verbose output
                break                                                            #Breaks the loop, ending the repetitive requests to the API



        endpoint_data = json.loads(urlopen(api_url + 'getEndpointData?host={}&s={}'.format(host,         #Sends a request to the SSL Labs API to fetch endpoint data for the specified host + ip address
                                    main_request['endpoints'][0]['ipAddress'])).read().decode('utf-8'))  #['ipAddress'] retrieves the ip address of the analyzed endpoint from the previous analysis
        
        if user_args.verbose:         
            print('{}Analyze report message: {}{}\n'.format(Clr.YELLOW, endpoint_data['statusMessage'], Clr.RST))  #Prints the status message of the endpoint analysis

######## If cert is invalid ########

        if endpoint_data['statusMessage'] == 'Certificate not valid for domain name':      #If status message indicates that the cert is not valid, it returns 
            return context                                                                  #the current context without further processing
        
        context[host]['grade'] = main_request['endpoints'][0]['grade']
        context[host]['poodle_vuln'] = endpoint_data['details']['poodle']                  #Updates various fields in the 'context' dictionary with data from 'endpoint_data'
        context[host]['heartbleed_vuln'] = endpoint_data['details']['heartbleed']          #Updates various vulnerability fields such as 'poodle_vuln', 'heartbleed_vuln', etc.
        context[host]['heartbeat_vuln'] = endpoint_data['details']['heartbeat']             #with their corresponding values from 'endpoint_data'
        context[host]['freak_vuln'] = endpoint_data['details']['freak']
        context[host]['logjam_vuln'] = endpoint_data['details']['logjam']
        context[host]['drownVulnerable'] = endpoint_data['details']['drownVulnerable']

        return context         #Returns the updated 'context' dictionary
    
######## Extract SANs from an X.509 cert ########
    
    def get_cert_sans(self, x509cert):                          #Aims to extract Subject Alternative Names(SANs) from an X.509 cert
        san = ''                                                #Initializes an empty string to store the SANs
        ext_count = x509cert.get_extension_count()              #Retrieves the count of extensions present in the cert
        for i in range(0, ext_count):                           #It iterates over each extension
            ext = x509cert.get_extension(i)                     
            if 'subjectAltName' in str(ext.get_short_name()):   #For each extension, it checks if the extension's short name contains the string 'subjectAltName'
                san = ext._str_()                               #If so, it sets the 'san' variable in the string representation of the extension
            san = san.replace(',', ';')                         #Replaces commas with semicolons in the 'san' string to avoid breaking CSV output
            return san                                          #Returns the 'san' string containing the SANs
        
######## Extract + Organize Info including details about validity, expiration, issuer, etc. ########

    def get_cert_info(self, host, cert, resolved_ip):   #Extracts various info from an SSL cert and organizes them into a dictionary
        context = {}                                    #Creates an empty dictionary named 'context' to store the certificate info

        cert_subject = cert.get_subject()               

        context['host'] = host                          
        context['resolved_ip'] = resolved_ip
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O
        context['issuer_c'] = cert.get_issuer().countryName
        context['issuer_o'] = cert.get_issuer().organizationName
        context['issuer_ou'] = cert.get_issuer().organizationalUnitName
        context['issuer_cn'] = cert.get_issuer().commonName
        context['cert_sn'] = str(cert.get_serial_number())
        context['cert_sha1'] = cert.digest('sha1').decode()
        context['cert_alg'] = cert.get_signature_algorithm().decode()
        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.has_expired()
        context['cert_valid'] = False if cert.has_expired() else True

        # Valid from #
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')   #Extracts the 'Valid from' date from the SSL cert using the 'get_notBefore' method
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')                                 #Dates are converted from their original format(ASCII) to Python datetime
                                                                                                #Extracted dates are formatted into YYYY-MM-DD + stored in the 'context' dictionary under
        # Valid till #                                                                           #the keys 'valid_from' + 'valid_till'
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')
 
        # Validity days #                                                                       #Number of days the cert is valid for
        context['validity_days'] = (valid_till - valid_from).days

        # Validity in days from now #                                                           #Number of days remaining until the cert expires
        now = datetime.now()
        context['days_left'] = (valid_till - now).days

        # Valid days left #                                                                     #Similar to above, only it's based on the formatted 'Valid till' date in YYYY-MM-DD format
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'], '%Y-%m-%d') - datetime.now()).days

        if cert.has_expired():            #Updates class-level variables 'total_expired' + 'total_valid' based on whether the certificate has expired or not
            self.total_expired += 1
        else: 
            self.total_valid += 1

        # If the cert has less than 15 days validity #
        if context['valid_days_to_expire'] <= 15:            #If the cert has less or equal to 15 days of validity remaining, it increments the 'total_warning' counter
            self.total_warning += 1

        return context
    
######## Print info about host + SSL cert ########

    def print_status(self, host, context, analyze=False):

        print('\t{}[\u2713]{} {}\n\t{}'.format(Clr.GREEN if context[host]['cert_valid'] else Clr.RED, Clr.RST, host, '-' * (len(host) + 5)))  #'\u2713' = Certificate validity status, printed in green if cert is valid
        print('\t\tIssued domain: {}'.format(context[host]['issued_to']))                                                                      #and red if not
        print('\t\tIssued to: {}'.format(context[host]['issued_o']))
        print('\t\tIssued by: {} ({})'.format(context[host]['issuer_o'], context[host]['issuer_c']))
        print('\t\tServer IP: {}'.format(context[host]['resolved_ip']))
        print('\t\tValid from: {}'.format(context[host]['valid_from']))
        print('\t\tValid to: {} ({} days left)'.format(context[host]['valid_till'], context[host]['valid_days_to_expire']))
        print('\t\tValidity days: {}'.format(context[host]['validity_days']))
        print('\t\tCertificate valid: {}'.format(context[host]['cert_valid']))
        print('\t\tCertificate S/N: {}'.format(context[host]['cert_sn']))
        print('\t\tCertificate SHA1 FP: {}'.format(context[host]['cert_sha1']))
        print('\t\tCertificate version: {}'.format(context[host]['cert_ver']))
        print('\t\tCertificate algorithm: {}'.format(context[host]['cert_alg']))

        if analyze:                                                                              #If 'analyze' is 'True', it prints additional analysis results such as vulnerabilities
            print('\t\tCertificate grade: {}'.format(context[host]['grade']))
            print('\t\tPoodle vulnerability: {}'.format(context[host]['poodle_vuln']))
            print('\t\tHeartbleed vulnerability: {}'.format(context[host]['heartbleed_vuln']))
            print('\t\tHeartbeat vulnerability: {}'.format(context[host]['heartbeat_vuln']))
            print('\t\tFreak vulnerability: {}'.format(context[host]['freak_vuln']))
            print('\t\tLogjam vulnerability: {}'.format(context[host]['logjam_vuln']))
            print('\t\tDrown vulnerability: {}'.format(context[host]['drownVulnerable']))

        print('\t\tExpired: {}'.format(context[host]['cert_exp']))     #Prints the expiration status of the cert
        print('\t\tCertificate SANs: ')                                #Prints a label indicating that the following lines will list the cert's SANs

        for san in context[host]['cert_sans'].split(';'):              #This loop iterates over each SAN extracted from the 'context' dictionary, ';' is used to split this string into individual SANs 
            print('\t\t \\_ {}'.format(san.strip()))                   #Each SAN is printed with a backslash and underscore

        print('\n')                                                    #Prints a newline character to seperate info

######## Environment Setup for SSL cert analysis ########

    def show_result(self, user_args):     #'user_args' = User arguments containing info such as hosts to analyze + analysis options
        context = {}
        start_time = datetime.now()       #Records the current time to track the start time of the analysis
        hosts = user_args.hosts           #Retrieves the list of hosts to analyze from the 'user_args' parameter

        if not user_args.json_true and not user_args.summary_true:          #If neither JSON output nor summary output is requested,
            self.border_msg(' Analyzing {} host(s) '.format(len(hosts)))     #it prints a message indicating the number of hosts being analyzed using the 'border_msg' method

        if not user_args.json_true and user_args.analyze:                   #If JSON output is not requested + summary output is requested
            print('{}Warning: -a/--analyze is enabled. It takes more time...{}\n'.format(Clr.YELLOW, Clr.RST))

        for host in hosts:                                                             #It iterates over each host in the provided list of hosts
            if user_args.verbose:                                                      #If verbosity is enabled,
                print('{}Working on host: {}{}\n'.format(Clr.YELLOW, host, Clr.RST))    #it prints a message indicating the host it's currently working on

            host, port = self.filter_hostname(host)     #It calls the 'filter_hostname' method to extract the host + port number from the provided host string

######## Checks for duplicate hosts + skips if found ######## 

            if host in context.keys():   #Checks if current host being processes is already present in the 'context' dictionary keys
                continue                 #If host is there already, it skips further processing for this host and moves on to the next one

        try:
            if user_args.sock:           
                if user_args.verbose:    #If verbosity is enabled, it prints a message indicating that it's connecting via a SOCKS proxy
                    print('{}Socks proxy enabled, connecting via proxy{}\n'.format(Clr.YELLOW, Clr.RST))

                socks_host, socks_port  = self.filter_hostname(user_args.socks)         #If SOCKS proxy is enabled, it extracts the proxy host + port
                cert, resolved_ip = self.get_cert(host, port, socks_host, socks_port)   #Calls the 'get_cert' method to retrieve the SSL cert from the host
            else:                                                                       #If SOCKS proxy is enabled, it passes the proxy host + port to the 'get_cert' method
                cert, resolved_ip = self.get_cert(host, port)                           #Otherwise, it will only provide the host + port

        context[host] = self.get_cert_info(host, cert, resolved_ip)    #Assigns the certificate information obtained from the 'get_cert_info' method to the 'context' dictionary
        context[host]['tcp_port'] = int(port)                          #This line adds the TCP port used for the connection to the 'context' dictionary

######## Analyze the certificate if enabled ######## 

    if user_args.analyze:
        context = self.analyze_ssl(host, context, user_args)

    if not user_args.json_true and not user_args.summary_true:
        self.print_status(host, context, user_args.analyze)
except SSL.SysCallError:
    if not user_args.json_true:
        print('\t{}[\u2717]{} {:<20s} Failed: Misconfigured SSL/TLS\n'.format(Clr.RED, Clr.RST, host))
        self.total_failed += 1
except Exception as error:
    if not user_args.json_true:
        print('\t{}[\u2717]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))