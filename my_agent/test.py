"""
Advanced Search Engine with comprehensive post-search features.
Features: Summarization, Bookmarking, Information Extraction, and File Management.

Environment Variable Support:
1. Authentication tokens:
   - Uses auth_env_var parameter to read tokens from environment (e.g., GITHUB_TOKEN, GITLAB_TOKEN)
   - Example: http_request(method="GET", url="...", auth_type="token", auth_env_var="GITHUB_TOKEN")
   - Supported variables: GITHUB_TOKEN, GITLAB_TOKEN, SLACK_BOT_TOKEN, AWS_ACCESS_KEY_ID, etc.
2. AWS credentials:
   - Reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION automatically
   - Example: http_request(method="GET", url="...", auth_type="aws_sig_v4", aws_auth={"service": "s3"})
Use the environment tool (agent.tool.environment) to view available environment variables:
- List all: environment(action="list")
- Get specific: environment(action="get", name="GITHUB_TOKEN")
- Set new: environment(action="set", name="CUSTOM_TOKEN", value="your-token")
"""

import base64
import collections
import datetime
import http.cookiejar
import json
import os
import time
from typing import Any, Dict, Optional, Union, List
from urllib.parse import urlparse, parse_qs, quote_plus
from html import unescape
import re
import hashlib

import markdownify
import readabilipy.simple_json
import requests
from aws_requests_auth.aws_auth import AWSRequestsAuth
from requests.adapters import HTTPAdapter
from rich import box
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.console import Console
from strands.types.tools import (
    ToolResult,
    ToolUse,
)
from urllib3 import Retry

from strands_tools.utils import console_util
from strands_tools.utils.user_input import get_user_input

TOOL_SPEC = {
    "name": "http_request",
    "description": (
        "Make HTTP requests to any API with comprehensive authentication including Bearer tokens, Basic auth, "
        "JWT, AWS SigV4, Digest auth, and enterprise authentication patterns. Automatically reads tokens from "
        "environment variables (GITHUB_TOKEN, GITLAB_TOKEN, AWS credentials, etc.) when auth_env_var is specified. "
        "Use environment(action='list') to view available variables. Includes session management, metrics, "
        "streaming support, cookie handling, redirect control, and optional HTML to markdown conversion."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, PUT, DELETE, etc.)",
                },
                "url": {
                    "type": "string",
                    "description": "The URL to send the request to",
                },
                "auth_type": {
                    "type": "string",
                    "enum": [
                        "Bearer",
                        "token",
                        "basic",
                        "digest",
                        "jwt",
                        "aws_sig_v4",
                        "kerberos",
                        "custom",
                        "api_key",
                    ],
                    "description": "Authentication type to use",
                },
                "auth_token": {
                    "type": "string",
                    "description": "Authentication token (if not provided, will check environment variables)",
                },
                "auth_env_var": {
                    "type": "string",
                    "description": "Name of environment variable containing the auth token",
                },
                "headers": {
                    "type": "object",
                    "description": "HTTP headers as key-value pairs",
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST, PUT, etc.)",
                },
                "verify_ssl": {
                    "type": "boolean",
                    "description": "Whether to verify SSL certificates",
                },
                "cookie": {
                    "type": "string",
                    "description": "Path to cookie file to use for the request",
                },
                "cookie_jar": {
                    "type": "string",
                    "description": "Path to cookie jar file to save cookies to",
                },
                "session_config": {
                    "type": "object",
                    "description": "Session configuration (cookies, keep-alive, etc)",
                    "properties": {
                        "keep_alive": {"type": "boolean"},
                        "max_retries": {"type": "integer"},
                        "pool_size": {"type": "integer"},
                        "cookie_persistence": {"type": "boolean"},
                    },
                },
                "metrics": {
                    "type": "boolean",
                    "description": "Whether to collect request metrics",
                },
                "streaming": {
                    "type": "boolean",
                    "description": "Enable streaming response handling",
                },
                "allow_redirects": {
                    "type": "boolean",
                    "description": "Whether to follow redirects (default: True)",
                },
                "max_redirects": {
                    "type": "integer",
                    "description": "Maximum number of redirects to follow (default: 30)",
                },
                "convert_to_markdown": {
                    "type": "boolean",
                    "description": "Convert HTML responses to markdown format (default: False).",
                },
                "aws_auth": {
                    "type": "object",
                    "description": "AWS auth configuration for SigV4",
                    "properties": {
                        "service": {"type": "string"},
                        "region": {"type": "string"},
                        "access_key": {"type": "string"},
                        "secret_key": {"type": "string"},
                        "session_token": {"type": "string"},
                        "refresh_credentials": {"type": "boolean"},
                    },
                },
                "basic_auth": {
                    "type": "object",
                    "description": "Basic auth credentials",
                    "properties": {
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                    },
                    "required": ["username", "password"],
                },
                "digest_auth": {
                    "type": "object",
                    "description": "Digest auth credentials",
                    "properties": {
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                        "realm": {"type": "string"},
                    },
                },
                "jwt_config": {
                    "type": "object",
                    "description": "JWT configuration",
                    "properties": {
                        "secret": {"type": "string"},
                        "algorithm": {"type": "string"},
                        "expiry": {"type": "integer"},
                    },
                },
            },
            "required": ["method", "url"],
        }
    },
}

# Session cache keyed by domain
SESSION_CACHE = {}

# Metrics storage
REQUEST_METRICS = collections.defaultdict(list)

# Configuration
BOOKMARKS_FILE = "bookmarks.json"
EXTRACTS_DIR = "extracted_info"
SUMMARIES_DIR = "summaries"

def ensure_directories():
    """Create necessary directories if they don't exist."""
    for dir_name in [EXTRACTS_DIR, SUMMARIES_DIR]:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)

def extract_content_from_html(html: str) -> str:
    """Extract and convert HTML content to Markdown format.

    Args:
        html: Raw HTML content to process

    Returns:
        Simplified markdown version of the content, or original HTML if conversion fails
    """
    try:
        ret = readabilipy.simple_json.simple_json_from_html_string(html, use_readability=True)
        if not ret.get("content"):
            return html

        content = markdownify.markdownify(
            ret["content"],
            heading_style=markdownify.ATX,
        )
        return content
    except Exception:
        # If conversion fails, return original HTML
        return html


def create_session(config: Dict[str, Any]) -> requests.Session:
    """Create and configure a requests Session object."""
    session = requests.Session()

    if config.get("keep_alive", True):
        adapter = HTTPAdapter(
            pool_connections=config.get("pool_size", 10),
            pool_maxsize=config.get("pool_size", 10),
            max_retries=Retry(
                total=config.get("max_retries", 3),
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504],
            ),
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

    if not config.get("cookie_persistence", True):
        session.cookies.clear()

    return session


def get_cached_session(url: str, config: Dict[str, Any]) -> requests.Session:
    """Get or create a cached session for the domain."""
    domain = urlparse(url).netloc
    if domain not in SESSION_CACHE:
        SESSION_CACHE[domain] = create_session(config)
    return SESSION_CACHE[domain]


def process_metrics(start_time: float, response: requests.Response) -> Dict[str, Any]:
    """Process and store request metrics."""
    end_time = time.time()
    metrics = {
        "duration": round(end_time - start_time, 3),
        "status_code": response.status_code,
        "bytes_sent": (len(response.request.body) if response.request and response.request.body is not None else 0),
        "bytes_received": len(response.content),
        "timestamp": datetime.datetime.now().isoformat(),
    }
    REQUEST_METRICS[urlparse(response.url).netloc].append(metrics)
    return metrics


def _search_brave(query: str, top_n: int = 5) -> list[dict]:
    """
    Uses Brave Search API if BRAVE_API_KEY is present.
    https://api.search.brave.com/res/v1/web/search
    """
    api_key = os.getenv("BRAVE_API_KEY")
    if not api_key:
        return []

    url = "https://api.search.brave.com/res/v1/web/search"
    headers = {"X-Subscription-Token": api_key}
    params = {"q": query, "count": max(1, min(top_n, 20))}
    resp = requests.get(url, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    results = data.get("web", {}).get("results", [])
    return [{"title": r.get("title"), "url": r.get("url"), "snippet": r.get("description", "")} for r in results[:top_n] if r.get("url")]

def _search_bing(query: str, top_n: int = 5) -> list[dict]:
    """
    Uses Bing Web Search v7 if BING_SEARCH_V7_SUBSCRIPTION_KEY is present.
    https://api.bing.microsoft.com/v7.0/search
    """
    api_key = os.getenv("BING_SEARCH_V7_SUBSCRIPTION_KEY")
    if not api_key:
        return []

    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": api_key}
    params = {"q": query, "count": max(1, min(top_n, 50))}
    resp = requests.get(url, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    items = (data.get("webPages", {}) or {}).get("value", [])
    return [{"title": i.get("name"), "url": i.get("url"), "snippet": i.get("snippet", "")} for i in items[:top_n] if i.get("url")]

def _search_duckduckgo(query: str, top_n: int = 5) -> list[dict]:
    """
    Fallback: scrape DuckDuckGo's HTML endpoint (no API key).
    We extract the destination from duckduckgo redirect links (?uddg=...).
    """
    url = "https://html.duckduckgo.com/html/"
    resp = requests.post(url, data={"q": query}, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
    resp.raise_for_status()
    html_text = resp.text

    results = []
    # Find anchors that look like result links with snippets
    for m in re.finditer(r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>(.*?)<a class="result__snippet"', html_text, flags=re.I|re.S):
        href = unescape(m.group(1))
        title_html = m.group(2)
        snippet_area = m.group(3)
        
        # Extract title
        title = re.sub(r"<.*?>", "", title_html).strip()
        
        # Extract snippet from the area between title and snippet link
        snippet_match = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', snippet_area, re.I|re.S)
        snippet = ""
        if snippet_match:
            snippet = re.sub(r"<.*?>", "", snippet_match.group(1)).strip()
        
        if href.startswith("/"):
            href = "https://duckduckgo.com" + href
        parsed = urlparse(href)
        qs = parse_qs(parsed.query)
        dest = qs.get("uddg", [None])[0] or href
        
        if dest and dest.startswith("http"):
            results.append({"title": title or dest, "url": dest, "snippet": snippet})
            if len(results) >= top_n:
                break
    return results

def search_web(query: str, top_n: int = 5) -> list[dict]:
    """
    Try Brave -> Bing -> DuckDuckGo and return up to top_n dicts with {title, url, snippet}.
    """
    for func in (_search_brave, _search_bing, _search_duckduckgo):
        try:
            hits = func(query, top_n=top_n)
            if hits:
                return hits[:top_n]
        except Exception:
            continue
    return []

def print_search_results(results: list[dict]) -> None:
    """Print search results with enhanced formatting."""
    if not results:
        print("No results found.")
        return
    
    console = Console()
    
    # Create a table for better formatting
    table = Table(title="Search Results", box=box.ROUNDED, show_header=True, header_style="bold blue")
    table.add_column("#", style="cyan", width=3)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Snippet", style="dim white", min_width=40)
    table.add_column("URL", style="blue", min_width=30)
    
    for i, result in enumerate(results, 1):
        title = result.get("title", "")[:60] + ("..." if len(result.get("title", "")) > 60 else "")
        snippet = result.get("snippet", "")[:80] + ("..." if len(result.get("snippet", "")) > 80 else "")
        url = result.get("url", "")
        # Truncate long URLs for display
        display_url = url[:50] + ("..." if len(url) > 50 else "")
        
        table.add_row(str(i), title, snippet, display_url)
    
    console.print(table)

def get_page_content(url: str) -> str:
    """Fetch and extract readable content from a webpage."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Extract readable content
        content = extract_content_from_html(response.text)
        return content
    except Exception as e:
        return f"Error fetching content: {str(e)}"

def generate_summary(content: str, max_length: int = 500) -> str:
    """Generate a simple summary by extracting key sentences."""
    if not content or len(content) < 100:
        return content
    
    # Simple summarization by taking first few sentences and key paragraphs
    sentences = re.split(r'[.!?]\s+', content)
    
    # Take first 2 sentences and a few more from the middle
    summary_sentences = []
    if len(sentences) > 0:
        summary_sentences.extend(sentences[:2])  # First 2 sentences
    
    if len(sentences) > 5:
        mid_point = len(sentences) // 2
        summary_sentences.extend(sentences[mid_point:mid_point+2])  # 2 from middle
    
    summary = '. '.join(summary_sentences)
    
    # Truncate if too long
    if len(summary) > max_length:
        summary = summary[:max_length] + "..."
    
    return summary

def load_bookmarks() -> List[Dict]:
    """Load bookmarks from JSON file."""
    if os.path.exists(BOOKMARKS_FILE):
        try:
            with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def save_bookmarks(bookmarks: List[Dict]) -> None:
    """Save bookmarks to JSON file."""
    with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
        json.dump(bookmarks, f, indent=2, ensure_ascii=False)

def add_bookmark(result: Dict) -> None:
    """Add a result to bookmarks."""
    bookmarks = load_bookmarks()
    
    # Check if already bookmarked
    for bookmark in bookmarks:
        if bookmark['url'] == result['url']:
            print("This URL is already bookmarked!")
            return
    
    bookmark = {
        "title": result['title'],
        "url": result['url'],
        "snippet": result.get('snippet', ''),
        "bookmarked_at": datetime.datetime.now().isoformat(),
        "tags": []
    }
    
    # Allow user to add tags
    tags_input = input("Add tags (comma-separated, optional): ").strip()
    if tags_input:
        bookmark['tags'] = [tag.strip() for tag in tags_input.split(',')]
    
    bookmarks.append(bookmark)
    save_bookmarks(bookmarks)
    print(f"Bookmarked: {result['title']}")

def view_bookmarks() -> None:
    """Display all bookmarks."""
    bookmarks = load_bookmarks()
    if not bookmarks:
        print("No bookmarks found.")
        return
    
    console = Console()
    table = Table(title="Your Bookmarks", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Tags", style="green", min_width=15)
    table.add_column("Date", style="dim", min_width=12)
    table.add_column("URL", style="blue", min_width=30)
    
    for i, bookmark in enumerate(bookmarks, 1):
        title = bookmark['title'][:50] + ("..." if len(bookmark['title']) > 50 else "")
        tags = ", ".join(bookmark.get('tags', []))
        date = bookmark['bookmarked_at'][:10]  # Just the date part
        url = bookmark['url'][:50] + ("..." if len(bookmark['url']) > 50 else "")
        
        table.add_row(str(i), title, tags, date, url)
    
    console.print(table)

def extract_and_save_info(result: Dict) -> None:
    """Extract specific information from a webpage and save to file."""
    ensure_directories()
    
    print(f"Fetching content from: {result['title']}")
    content = get_page_content(result['url'])
    
    if content.startswith("Error"):
        print(content)
        return
    
    print("What type of information would you like to extract?")
    print("1. Email addresses")
    print("2. Phone numbers") 
    print("3. Dates")
    print("4. URLs/Links")
    print("5. Custom text pattern")
    print("6. All text content")
    
    choice = input("Choose extraction type (1-6): ").strip()
    
    extracted = ""
    filename_suffix = ""
    
    if choice == "1":
        # Extract email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        extracted = "\n".join(set(emails))  # Remove duplicates
        filename_suffix = "emails"
    elif choice == "2":
        # Extract phone numbers (basic pattern)
        phones = re.findall(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b', content)
        extracted = "\n".join(set(phones))
        filename_suffix = "phones"
    elif choice == "3":
        # Extract dates (various formats)
        dates = re.findall(r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4})\b', content, re.IGNORECASE)
        extracted = "\n".join(set(dates))
        filename_suffix = "dates"
    elif choice == "4":
        # Extract URLs
        urls = re.findall(r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?', content)
        extracted = "\n".join(set(urls))
        filename_suffix = "urls"
    elif choice == "5":
        # Custom pattern
        pattern = input("Enter regex pattern to search for: ").strip()
        try:
            matches = re.findall(pattern, content, re.IGNORECASE)
            extracted = "\n".join(set(matches))
            filename_suffix = "custom"
        except re.error as e:
            print(f"Invalid regex pattern: {e}")
            return
    elif choice == "6":
        # Full content
        extracted = content
        filename_suffix = "content"
    else:
        print("Invalid choice")
        return
    
    if not extracted.strip():
        print("No matching information found.")
        return
    
    # Generate filename
    safe_title = re.sub(r'[^\w\s-]', '', result['title'])[:50]
    safe_title = re.sub(r'[-\s]+', '_', safe_title)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_title}_{filename_suffix}_{timestamp}.txt"
    filepath = os.path.join(EXTRACTS_DIR, filename)
    
    # Save to file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Extracted from: {result['title']}\n")
        f.write(f"URL: {result['url']}\n")
        f.write(f"Extraction Date: {datetime.datetime.now().isoformat()}\n")
        f.write(f"Extraction Type: {filename_suffix}\n")
        f.write("=" * 50 + "\n\n")
        f.write(extracted)
    
    print(f"Information extracted and saved to: {filepath}")
    print(f"Found {len(extracted.split('\\n')) if extracted else 0} items.")

def create_summary(result: Dict) -> None:
    """Create and save a summary of the webpage content."""
    ensure_directories()
    
    print(f"Creating summary for: {result['title']}")
    content = get_page_content(result['url'])
    
    if content.startswith("Error"):
        print(content)
        return
    
    # Generate summary
    summary = generate_summary(content, max_length=1000)
    
    # Generate filename
    safe_title = re.sub(r'[^\w\s-]', '', result['title'])[:50]
    safe_title = re.sub(r'[-\s]+', '_', safe_title)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_title}_summary_{timestamp}.txt"
    filepath = os.path.join(SUMMARIES_DIR, filename)
    
    # Save summary
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Summary of: {result['title']}\n")
        f.write(f"URL: {result['url']}\n")
        f.write(f"Summary Date: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 50 + "\n\n")
        f.write("SUMMARY:\n")
        f.write(summary)
        f.write("\n\n" + "=" * 50 + "\n")
        f.write("FULL CONTENT:\n")
        f.write(content[:5000] + ("..." if len(content) > 5000 else ""))  # Truncated full content
    
    print(f"Summary saved to: {filepath}")
    print(f"\nSummary preview:\n{summary[:200]}...")

def show_action_menu() -> str:
    """Display the action menu and get user choice."""
    print("\nWhat would you like to do?")
    print("1. Get summary of page")
    print("2. Bookmark this link")
    print("3. Extract specific information")
    print("4. View all bookmarks")
    print("5. Open link in browser")
    print("6. Search again")
    print("7. Exit")
    
    return input("Choose action (1-7): ").strip()

def main():
    """Enhanced main function with comprehensive search features."""
    try:
        ensure_directories()
        
        console = Console()
        console.print(Panel.fit(
            "[bold blue]Advanced Search Engine[/bold blue]\n" +
            "Features: Summarization, Bookmarking, Information Extraction",
            style="blue"
        ))
        
        while True:
            # Get search query
            print("\n" + "="*60)
            query = input("Enter your search query (or 'bookmarks' to view bookmarks, 'quit' to exit): ").strip()
            
            if query.lower() == 'quit':
                break
            elif query.lower() == 'bookmarks':
                view_bookmarks()
                continue
            elif not query:
                print("Please enter a search query.")
                continue
            
            # Perform search
            print(f"\nSearching for: {query}")
            results = search_web(query, top_n=10)
            
            if not results:
                print("No results found. Try a different query.")
                continue
            
            # Display results
            print_search_results(results)
            
            while True:
                # Get user selection
                try:
                    choice = input(f"\nSelect a result (1-{len(results)}) or 'back' for new search: ").strip().lower()
                    
                    if choice == 'back':
                        break
                    
                    result_index = int(choice) - 1
                    if 0 <= result_index < len(results):
                        selected_result = results[result_index]
                        
                        print(f"\nSelected: {selected_result['title']}")
                        print(f"URL: {selected_result['url']}")
                        
                        # Show action menu
                        while True:
                            action = show_action_menu()
                            
                            if action == '1':
                                create_summary(selected_result)
                            elif action == '2':
                                add_bookmark(selected_result)
                            elif action == '3':
                                extract_and_save_info(selected_result)
                            elif action == '4':
                                view_bookmarks()
                            elif action == '5':
                                print(f"Would open: {selected_result['url']}")
                                print("(Browser integration not implemented)")
                            elif action == '6':
                                break  # Back to search
                            elif action == '7':
                                return
                            else:
                                print("Invalid choice. Please try again.")
                                continue
                            
                            # Ask if user wants to do another action on the same result
                            another = input("\nPerform another action on this result? (y/n): ").strip().lower()
                            if another != 'y':
                                break
                        
                        break  # Back to result selection or new search
                    else:
                        print(f"Please enter a number between 1 and {len(results)}")
                        
                except ValueError:
                    print("Please enter a valid number or 'back'")
                    
    except KeyboardInterrupt:
        print("\n\nSearch session ended.")
    except Exception as e:
        print(f"\nError: {e}")

# Additional utility functions for file management
def list_saved_files():
    """List all saved summaries and extracts."""
    print("\nSaved Files:")
    print("-" * 40)
    
    if os.path.exists(SUMMARIES_DIR):
        summaries = os.listdir(SUMMARIES_DIR)
        if summaries:
            print(f"\nSummaries ({len(summaries)} files):")
            for f in sorted(summaries)[:10]:  # Show latest 10
                print(f"  {f}")
            if len(summaries) > 10:
                print(f"  ... and {len(summaries) - 10} more")
    
    if os.path.exists(EXTRACTS_DIR):
        extracts = os.listdir(EXTRACTS_DIR)
        if extracts:
            print(f"\nExtracts ({len(extracts)} files):")
            for f in sorted(extracts)[:10]:  # Show latest 10
                print(f"  {f}")
            if len(extracts) > 10:
                print(f"  ... and {len(extracts) - 10} more")

if __name__ == "__main__":
    main()