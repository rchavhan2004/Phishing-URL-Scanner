import tldextract
import Levenshtein as lv

legitimate_domains = {'example.com', 'google.com', 'facebook.com'}

def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.domain.lower(), extracted.suffix.lower(), extracted.subdomain.lower()

def is_misspelled_domain(domain, legitimate_domains, threshold=0.1):
    for legitimate_domain in legitimate_domains:
        legit_base_domain = legitimate_domain.split('.')[0]  # Extract base domain
        similarity = lv.ratio(domain, legit_base_domain)
        if similarity >= threshold:
            return True
    return False

def is_phishing_url(url, legitimate_domains):
    domain, suffix, subdomain = extract_domain_parts(url)

    full_domain = f"{domain}.{suffix}"
    full_with_subdomain = f"{subdomain}.{domain}.{suffix}" if subdomain else full_domain

    if full_domain in legitimate_domains or full_with_subdomain in legitimate_domains:
        return False

    if is_misspelled_domain(domain, legitimate_domains):
        print(f"Potential phishing detected (misspelled domain): {url}")
        return True

    for legitimate_domain in legitimate_domains:
        if legitimate_domain in full_with_subdomain and not full_domain.startswith(legitimate_domain):
            print(f"Potential phishing detected (subdomain misuse): {url}")
            return True

    return False

if __name__ == "__main__":
    print("Enter URLs separated by commas:")
    user_input = input()  # Get URLs from the user
    test_urls = set(user_input.split(','))

    for url in test_urls:
        if not is_phishing_url(url, legitimate_domains):
            print(f"Legitimate URL: {url}")
