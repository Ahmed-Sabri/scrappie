#!/usr/bin/env python3
import os
import sys
import csv
import asyncio
import subprocess
import re
import json
from pathlib import Path
import pandas as pd
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

# Email and phone validation functions, run [python scrappie.py -d domains.txt]
def validate_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)

def validate_phone(phone):
    regex = r'^\+?\d{7,15}$'  # International format or at least 7 digits
    return re.match(regex, phone)

# BBOT fallback using Docker
def bbot_extract_emails(domain):
    try:
        print(f"Using aggressive scrapper to extract emails for: {domain}")
        cmd = [
            "docker", "run", "--rm",
            "blacklanternsecurity/bbot:stable",
            "-t", domain,
            "-f", "email-enum",
            "-o", "json"
        ]

        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        ).stdout

        # Extract emails using grep-like filtering
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', output)
        emails = list(set(filter(None, emails)))  # Deduplicate and remove empty strings
        return emails

    except subprocess.TimeoutExpired:
        print(f"Timeout while processing {domain} with BBOT")
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error processing {domain} with BBOT: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error with BBOT: {e}")
        return []

# Web scraping with BeautifulSoup and Playwright
async def scrape_contact_details(url):
    if not url.startswith("http"):
        url = f"https://{url}"

    extracted_emails = []
    extracted_phones = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=10000)
            content = await page.content()
            soup = BeautifulSoup(content, "html.parser")

            # Extract emails
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
            extracted_emails.extend(filter(validate_email, emails))

            # Extract phone numbers
            phones = re.findall(r'\+?\d{7,15}', content)
            extracted_phones.extend(filter(validate_phone, phones))

        except Exception as e:
            print(f"Error scraping {url}: {e}")
        finally:
            await browser.close()

    return list(set(extracted_emails)), list(set(extracted_phones))  # Deduplicate

# Unified processing function
async def process_domains(domains):
    results = []
    for domain in domains:
        print(f"\nProcessing: {domain}")
        emails, phones = await scrape_contact_details(domain)

        if not emails:
            # Fallback to BBOT if no emails found via scraping
            emails = bbot_extract_emails(domain)

        results.append({
            "Domain": domain,
            "Emails": ", ".join(emails),
            "Phone Numbers": ", ".join(phones)
        })

    return results

# Save results to CSV
def save_results_to_csv(results, output_file="contact_results.csv"):
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Domain", "Emails", "Phone Numbers"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults saved to {output_file}")

# Main function
async def main(domain_file):
    if not os.path.exists(domain_file):
        print(f"Error: File {domain_file} does not exist")
        sys.exit(1)

    with open(domain_file, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    results = await process_domains(domains)
    save_results_to_csv(results)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Hybrid contact scraper and email extractor")
    parser.add_argument("-d", "--domains", required=True, help="Path to file containing domain list")
    args = parser.parse_args()

    asyncio.run(main(args.domains))
