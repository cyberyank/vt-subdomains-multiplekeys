#!/usr/bin/env python3
import requests
import sys
import time

# Add your API keys here
API_KEYS = [
    '1',
    '2',
    '3',
    '4',
]

def fetch_subdomains(domain, output_file):
    current_key_index = 0
    url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
    subdomains = set()
    
    with open(output_file, 'w') as f:
        while url:
            # Get current API key
            api_key = API_KEYS[current_key_index]
            headers = {'x-apikey': api_key}
            
            print(f"Requesting with key {current_key_index + 1}/{len(API_KEYS)}")
            
            try:
                resp = requests.get(url, headers=headers)
                
                if resp.status_code == 429:
                    print(f"Quota exceeded for key {current_key_index + 1}")
                    # Rotate to next key
                    current_key_index = (current_key_index + 1) % len(API_KEYS)
                    continue
                    
                elif resp.status_code != 200:
                    print(f"Error {resp.status_code}: {resp.text}")
                    break
                
                data = resp.json()
                new_count = 0
                
                for item in data.get('data', []):
                    subdomain = item['id']
                    if subdomain not in subdomains:
                        print(f"  {subdomain}")
                        f.write(subdomain + '\n')
                        f.flush()  # Save immediately
                        subdomains.add(subdomain)
                        new_count += 1
                
                print(f"Found {new_count} new subdomains. Total: {len(subdomains)}")
                
                # Get next page URL
                url = data.get('links', {}).get('next')
                
                # Rotate to next key for next request
                current_key_index = (current_key_index + 1) % len(API_KEYS)
                
                # Small delay between requests
                if url:
                    time.sleep(1)
                    
            except Exception as e:
                print(f"Request error: {e}")
                break
    
    print(f"\nFinished! Total subdomains: {len(subdomains)}")
    return len(subdomains)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 vt-subdomains-multipleapikeys.py domain.com")
        print("Make sure to update the API_KEYS list!")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_file = f"subdomains_{domain.replace('.', '_')}.txt"
    
    print(f"Starting subdomain collection for {domain}")
    print(f"Using {len(API_KEYS)} API keys")
    print(f"Output file: {output_file}")
    
    total = fetch_subdomains(domain, output_file)
    print(f"Saved {total} subdomains to {output_file}") 
