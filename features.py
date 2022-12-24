import csv
import re
from urllib.parse import urlparse
import tldextract

# Open the input and output files
with open('labelled_url.csv', 'r', encoding="ISO-8859-1" ) as input_file, open('featured_url.csv', 'w', newline="") as output_file:
    # Create a CSV reader and writer
    reader = csv.reader(input_file)
    writer = csv.writer(output_file)

    # Write the feature names to the output file
    writer.writerow(['label', 'Length Of URL', 'Length of Hostname', 'Length of Subdomains', 'Length Of Path', 'Length Of Query Parameters', 'Length Of First Directory', 'Length Of Top Level Domain', 'Count Of "-"', 'Count Of "@"', 'Count Of "?"', 'Count Of "%"', 'Count Of "."', 'Count Of "//"', 'Count Of "+"', 'Count Of "="', 'Count Of "&"', 'Count Of "http"', 'Count Of "www"', 'Count Of Digits', 'Count Of Letters', 'Count Of Number Of Directories', 'Use of encoded characters in query parameters', 'Use of special characters in hostname', 'Use of encdoed characters in path', 'Use of special characters in path', 'Use of known-directory name for malicious content', 'Use of multiple redirectes', 'Use of non-standard top-level domains', 'Use of https protocol', 'Use ofknown-query string structure for malicious content', 'Use of special characters in hostname', 'Use of IP address or not', 'Use of Shortening URL or not', 'Presence of query parameters', 'Presence of subdomains', 'Presence of long URL', 'Presence of long path', 'Presence of long query string'])


    # Iterate over the rows in the input file
    for row in reader:
        if row[0] == 'url':
            continue
        else:
            # Parse the URL
            label = row[1]
            parsed_url = urlparse(row[0])
            extracted_url = tldextract.extract(row[0])

            # Extract the features
            length_of_url = len(row[0])
            length_of_subdomains = len(extracted_url.subdomain) if extracted_url.subdomain != None else 0
            length_of_path = len(parsed_url.path)
            length_of_query_parameters = len(parsed_url.query)    
            try:
                length_of_first_directory = len(parsed_url.path.split('/')[1])
            except:
                length_of_first_directory = 0
            try:
                length_of_top_level_domain = len(extracted_url.suffix)
            except:
                length_of_top_level_domain = 0
            try:
                length_of_hostname = len(parsed_url.hostname)
                use_of_special_characters_in_hostname = 1 if any(not c.isalnum() for c in parsed_url.hostname) else 0
            except:
                length_of_hostname = 0
                use_of_special_characters_in_hostname = 0
                
            count_of_dash = row[0].count('-')
            count_of_at = row[0].count('@')
            count_of_question_mark = row[0].count('?')
            count_of_percent = row[0].count('%')
            count_of_period = row[0].count('.')
            count_of_double_slash = row[0].count('//')
            count_of_plus = row[0].count('+')
            count_of_equals = row[0].count('=')
            count_of_ampersand = row[0].count('&')
            count_of_http = row[0].count('http')
            count_of_www = row[0].count('www')
            count_of_digits = sum(c.isdigit() for c in row[0])
            count_of_letters = sum(c.isalpha() for c in row[0])
            count_of_number_of_directories = len(parsed_url.path.split('/')) - 1
            
            use_of_encoded_characters_in_query_parameters = 1 if any(c in parsed_url.query for c in ['%', '+']) else 0
            use_of_special_characters_in_query_parameters = 1 if any(c in parsed_url.query for c in ['#', '&', '?', '$', '=']) else 0
            use_of_encoded_characters_in_path = 1 if any(c in parsed_url.path for c in ['%', '+']) else 0
            use_of_special_characters_in_path = 1 if any(c in parsed_url.path for c in ['#', '&', '?', '$', '=']) else 0
            use_of_known_directory_name_for_malicious_content = 1 if any(dir_name in parsed_url.path.split('/') for dir_name in ['download', 'install']) else 0
            use_of_multiple_redirects = 1 if row[0].count('http') > 1 else 0
            use_of_non_standard_top_level_domains = 1 if extracted_url.suffix not in ['com', 'net', 'org', 'edu'] else 0
            use_of_https_protocol = 1 if parsed_url.scheme == 'https' else 0
            use_of_known_query_string_structure_for_malicious_content = 1 if any(param in parsed_url.query for param in ['id=', 'token=']) else 0
            use_of_ip_address = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', row[0]) else 0
            use_of_shortening_url = 1 if re.match(r'^https?:\/\/(www\.)?bit\.ly|tiny\.cc|tinyurl\.com|ow\.ly|is\.gd|shorte\.st|tiny\.ie|tiny\.pl|tiny\.re|tiny\.tl|tiny\.cc|tiny\.to|tiny\.ec|tiny\.ly|tiny\.be|tiny\.cc|tiny\.mw|tiny\.gs|tiny\.me|tiny\.vg|tiny\.ly|tiny\.vg|tiny\.tf|tiny\.cx|tiny\.tf|tiny\.fr|tiny\.ly|tiny\.gl|tiny\.ma|tiny\.gy|tiny\.pe|tiny\.ec|tiny\.yt|tiny\.pl|tiny\.vip|tiny\.ie|tiny\.co|tiny\.mu|tiny\.cc|tiny\.st', row[0]) else 0
            
            presence_of_query_parameters = 1 if parsed_url.query else 0
            presence_of_subdomains = 1 if extracted_url.subdomain else 0
            presence_of_long_URL = 1 if len(row[0]) > 200 else 0
            presence_of_long_path = 1 if len(parsed_url.path) > 100 else 0
            presence_of_long_query_string = 1 if len(parsed_url.query) > 100 else 0

            # Write the features to the output file
            writer.writerow([label, length_of_url, length_of_hostname, length_of_subdomains, length_of_path, length_of_query_parameters, length_of_first_directory, length_of_top_level_domain, count_of_dash, count_of_at, count_of_question_mark, count_of_percent, count_of_period, count_of_double_slash, count_of_plus, count_of_equals, count_of_ampersand, count_of_http, count_of_www, count_of_digits, count_of_letters, count_of_number_of_directories, use_of_encoded_characters_in_query_parameters, use_of_special_characters_in_query_parameters, use_of_encoded_characters_in_path, use_of_special_characters_in_path, use_of_known_directory_name_for_malicious_content, use_of_multiple_redirects, use_of_non_standard_top_level_domains, use_of_https_protocol,use_of_known_query_string_structure_for_malicious_content, use_of_special_characters_in_hostname, use_of_ip_address, use_of_shortening_url, presence_of_query_parameters, presence_of_subdomains, presence_of_long_URL, presence_of_long_path, presence_of_long_query_string])
