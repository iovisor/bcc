#! /usr/bin/env python3

import re
import requests
import os
from pathlib import Path

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
timeout = 10

links_file = Path('LINKS.md')
content = links_file.read_text(encoding='utf-8')

link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
links = link_pattern.findall(content)

broken_links = []
for text, url in links:
    try:
        print(f"Checking: {url}")
        response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        
        if response.status_code >= 400:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            
        if response.status_code >= 400:
            broken_links.append((text, url, response.status_code))
    except Exception as e:
        broken_links.append((text, url, str(e)))

if broken_links:
    report = "# Broken Links Report\n\n"
    report += "The following links in LINKS.md are broken:\n\n"
    report += "| Link Text | URL | Error |\n"
    report += "|-----------|-----|-------|\n"
    
    for text, url, error in broken_links:
        report += f"| {text} | {url} | {error} |\n"
        
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        delimiter = "_REPORT_DELIMITER_"
        f.write(f"broken_links=true\n")
        f.write(f"report<<{delimiter}\n{report}\n{delimiter}\n")
else:
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write("broken_links=false\n")