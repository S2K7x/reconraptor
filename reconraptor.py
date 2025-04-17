# recon_raptor.py (v4.0)
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnectionError
# Suppress only the single InsecureRequestWarning from urllib3 needed for verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from bs4 import BeautifulSoup, SoupStrainer
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import sys
import time
from collections import deque
import concurrent.futures
import logging
import re
import random
import os
import threading
import json
import urllib.robotparser
import xml.etree.ElementTree as ET

# --- Constants ---
__version__ = "4.0"
DEFAULT_TIMEOUT = 10
MAX_WORKERS_DEFAULT = 25
DEFAULT_DELAY = 0
DEFAULT_USER_AGENT = f'ReconRaptor/{__version__} (+https://github.com/your-repo)'
EXISTENCE_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403, 405}
ABSENCE_STATUS_CODES = {404, 410}
PARAM_LEN_DIFF_THRESHOLD = 25

# --- Default Wordlists ---
# (Same as v3.0)
DEFAULT_DIRS = [
    'admin', 'login', 'dashboard', 'app', 'api', 'test', 'dev', 'staging', 'prod',
    'backup', 'config', 'includes', 'assets', 'images', 'css', 'js', 'scripts',
    'uploads', 'files', 'static', 'vendor', 'node_modules', '.git', '.svn', '.hg',
    '.env', 'wp-admin', 'wp-content', 'wp-includes', 'administrator', 'phpmyadmin'
]
DEFAULT_FILES = [
    'index.php', 'index.html', 'index.htm', 'login.php', 'config.php', 'admin.php',
    'config.json', 'config.yaml', 'config.yml', 'settings.php', 'settings.json',
    'backup.zip', 'backup.sql', 'dump.sql', 'site.zip', 'env.txt', '.env', '.htaccess',
    'docker-compose.yml', 'Dockerfile', 'README.md', 'LICENSE', 'robots.txt',
    'sitemap.xml', 'crossdomain.xml', 'phpinfo.php', 'test.php', 'debug.php',
    'error_log', 'access_log', 'web.config', 'package.json', 'composer.json'
]
DEFAULT_EXTENSIONS = ['.php', '.html', '.htm', '.js', '.css', '.txt', '.json', '.xml', '.bak', '.old', '.zip', '.sql', '.log', '.ini', '.config', '.yml', '.yaml']
DEFAULT_PARAMS = [
    'id', 'user', 'username', 'pass', 'password', 'query', 'search', 'q', 's',
    'year', 'month', 'day', 'view', 'page', 'p', 'lang', 'debug', 'test', 'admin',
    'file', 'path', 'url', 'redirect', 'next', 'return', 'returnTo', 'goto', 'dest',
    'callback', 'continue', 'img', 'image', 'name', 'item', 'data', 'cmd', 'exec',
    'ip', 'host', 'domain', 'key', 'token', 'api_key', 'uid', 'email'
]
DEFAULT_API_PATHS = ['api', 'v1', 'v2', 'v3', 'graphql', 'rest', 'jsonrpc', 'xmlrpc', 'swagger', 'openapi']
DEFAULT_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'admin', 'administrator', 'webmail', 'test',
    'dev', 'staging', 'prod', 'api', 'app', 'blog', 'shop', 'store', 'support',
    'help', 'status', 'docs', 'developer', 'internal', 'vpn', 'remote', 'portal',
    'assets', 'static', 'cdn', 'images', 'js', 'css', 'files', 'uploads', 'backup'
]
JS_PATH_REGEX = re.compile(r'["\']((?:https?:)?//[^\s"\'\\,;\{\}\(\)]+|/[^\s"\'\\,;\{\}\(\)]+)["\']')
JS_RELATIVE_PATH_REGEX = re.compile(r'["\'](/[\w\-\./]+(?:[?#][^\s"\'\\,;\{\}\(\)]*)?)["\']')


# --- Logging Setup ---
log = logging.getLogger('ReconRaptor')
log.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
console_formatter = logging.Formatter('[%(levelname).1s] %(asctime)s %(message)s', datefmt='%H:%M:%S')
console_handler.setFormatter(console_formatter)
if not log.handlers:
    log.addHandler(console_handler)
file_handler = None

# --- Utility ---
def is_valid_url(url):
    """Basic check if a string looks like an HTTP/HTTPS URL."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ['http', 'https'], parsed.netloc])
    except ValueError:
        return False

def load_wordlist(filepath, default_list):
    """Loads wordlist from file, falls back to default list."""
    # (Same as v3.0)
    if filepath:
        log.info(f"Attempting to load wordlist from: {filepath}")
        try:
            if not os.path.exists(filepath):
                 log.error(f"Wordlist file not found: {filepath}. Using default list.")
                 return default_list
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                items = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if not items:
                 log.warning(f"Wordlist file is empty: {filepath}. Using default list.")
                 return default_list
            log.info(f"Loaded {len(items)} items from {filepath}")
            return items
        except IOError as e:
            log.error(f"Error reading wordlist file {filepath}: {e}. Using default list.")
            return default_list
        except Exception as e:
            log.error(f"Unexpected error loading wordlist file {filepath}: {e}. Using default list.")
            return default_list
    else:
        # Avoid logging default list usage every time
        # log.info(f"Using default internal wordlist for {type(default_list[0]) if default_list else 'items'}.")
        return default_list

def parse_header(header_string):
    """Parses a 'Header: Value' string into a tuple."""
    if ':' not in header_string:
        log.warning(f"Invalid header format: '{header_string}'. Skipping.")
        return None
    key, value = header_string.split(':', 1)
    return key.strip(), value.strip()

def parse_cookie(cookie_string):
    """Parses a 'key=value' cookie string into a tuple."""
    if '=' not in cookie_string:
        log.warning(f"Invalid cookie format: '{cookie_string}'. Skipping.")
        return None
    key, value = cookie_string.split('=', 1)
    return key.strip(), value.strip()

# --- Recon Runner Class ---
class ReconRunner:
    """Orchestrates the reconnaissance scan."""

    def __init__(self, target_url, modes, wordlist_paths, workers, delay, user_agent, timeout,
                 headers, cookies, insecure, follow_redirects, filters):
        """Initializes the ReconRunner."""
        if not is_valid_url(target_url):
            raise ValueError(f"Invalid starting URL: {target_url}")

        self.base_url = target_url.rstrip('/')
        self.target_host = urlparse(self.base_url).netloc
        self.target_scheme = urlparse(self.base_url).scheme
        self.modes = modes if any(modes.values()) else {k: True for k in modes} # Run all if none specified
        self.workers = workers
        self.delay = max(0, delay)
        self.timeout = timeout
        self.follow_redirects_path = follow_redirects # Specific for path checks
        self.filters = filters # Dictionary containing filter settings

        # Load wordlists
        self.wordlists = {
            'dirs': load_wordlist(wordlist_paths.get('dirs'), DEFAULT_DIRS),
            'files': load_wordlist(wordlist_paths.get('files'), DEFAULT_FILES),
            'extensions': load_wordlist(wordlist_paths.get('extensions'), DEFAULT_EXTENSIONS),
            'params': load_wordlist(wordlist_paths.get('params'), DEFAULT_PARAMS),
            'subdomains': load_wordlist(wordlist_paths.get('subdomains'), DEFAULT_SUBDOMAINS),
        }

        # Setup Session with custom headers/cookies
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': user_agent})
        if headers:
             for key, value in headers.items():
                  log.debug(f"Adding header: {key}: {value}")
                  self.session.headers.update({key: value})
        if cookies:
             for key, value in cookies.items():
                  log.debug(f"Adding cookie: {key}={value}")
                  self.session.cookies.set(key, value)
        self.check_ssl = not insecure
        if insecure:
             log.warning("SSL certificate verification disabled (--insecure).")


        self.found_items = {
            "dirs": set(), "files": set(), "endpoints": set(), "params": set(),
            "urls_with_params": set(), "subdomains": set(), "potential_params": {},
            "js_files": set()
        }
        self.processed_urls = set()
        self.lock = threading.Lock()

        log.info(f"ReconRaptor Scanner v{__version__} initialized.")
        log.info(f"Target: {self.base_url}, Workers: {self.workers}, Delay: {self.delay}s")
        log.info(f"Running Modes: {[k for k, v in self.modes.items() if v]}")
        log.info(f"Follow Redirects (Paths): {self.follow_redirects_path}, Verify SSL: {self.check_ssl}")
        log.info(f"Filters: {self.filters}")


    # --- Core Request/Check Methods ---
    def _make_request(self, url, method='GET', stream=False, allow_redirects=None):
        """Makes an HTTP request using the session, handles errors and SSL verification."""
        # Use instance redirect setting if not overridden
        redirects = self.follow_redirects_path if allow_redirects is None else allow_redirects
        try:
            if self.delay > 0: time.sleep(self.delay)
            response = self.session.request(
                method, url, timeout=self.timeout, stream=stream,
                allow_redirects=redirects, verify=self.check_ssl
            )
            return response
        except Timeout: log.warning(f"Timeout requesting: {url}"); return None
        except ReqConnectionError: log.warning(f"Connection error for: {url}"); return None
        # Catch SSL errors specifically if verify=True
        except requests.exceptions.SSLError as e: log.warning(f"SSL Error for {url}: {e}. Try --insecure?"); return None
        except RequestException as e: log.warning(f"Request exception for {url}: {e}"); return None
        except Exception as e: log.error(f"Unexpected error during request to {url}: {e}"); return None

    def _apply_filters(self, response):
        """Checks if a response passes the defined filters."""
        if response is None: return False # Cannot filter None response

        status = response.status_code
        content_len = int(response.headers.get('Content-Length', -1)) # Use -1 if header missing

        # Status Code Filters
        if self.filters['include_status'] and status not in self.filters['include_status']:
            log.debug(f"Filtering out {response.url} (Status: {status} not in include list)")
            return False
        if self.filters['exclude_status'] and status in self.filters['exclude_status']:
            log.debug(f"Filtering out {response.url} (Status: {status} in exclude list)")
            return False

        # Content Length Filters (only if length is known)
        # For HEAD requests, content_len might be -1 or inaccurate.
        # We might need a GET request if length filters are active.
        # This logic is now moved into _check_path for better handling.
        if self.filters['min_length'] is not None and content_len >= 0 and content_len < self.filters['min_length']:
             log.debug(f"Filtering out {response.url} (Length: {content_len} < {self.filters['min_length']})")
             return False
        if self.filters['max_length'] is not None and content_len >= 0 and content_len > self.filters['max_length']:
             log.debug(f"Filtering out {response.url} (Length: {content_len} > {self.filters['max_length']})")
             return False

        return True # Passed all filters

    def _check_path(self, path_segment):
        """Checks if a directory or file path exists, applying filters."""
        base_path = urlparse(self.base_url).path
        if base_path and base_path != '/' and path_segment.startswith('/'): path_segment = path_segment[1:]
        target_url = urljoin(self.base_url + ('/' if not self.base_url.endswith('/') else ''), path_segment.lstrip('/'))
        if target_url in self.processed_urls and target_url != self.base_url: return

        log.debug(f"Checking path: {target_url}")
        # Use GET request directly if filtering by length, otherwise try HEAD first
        needs_get_for_filter = self.filters['min_length'] is not None or self.filters['max_length'] is not None
        initial_method = 'GET' if needs_get_for_filter else 'HEAD'

        response = self._make_request(target_url, method=initial_method, allow_redirects=self.follow_redirects_path, stream=needs_get_for_filter)

        # If HEAD failed or timed out, try GET (unless GET already tried)
        if response is None and initial_method == 'HEAD':
             response = self._make_request(target_url, method='GET', allow_redirects=self.follow_redirects_path, stream=True)

        if response is not None:
            # If redirects were followed, the final URL might be different
            final_url = response.url
            status = response.status_code
            content_type = response.headers.get('Content-Type', '').lower()
            content_len_str = response.headers.get('Content-Length')
            content_len = -1
            # Get actual content length if needed for filtering and not present/accurate in headers
            if needs_get_for_filter and content_len_str is None:
                 # If streamed, read content to get length
                 if initial_method == 'GET' and response.raw:
                      try:
                           # Read content carefully, respecting timeout implicitly via session timeout?
                           actual_content = response.content # This reads the full content
                           content_len = len(actual_content)
                           log.debug(f"Read content for length filter: {final_url} (Length: {content_len})")
                      except Exception as e:
                           log.warning(f"Error reading content for length filter on {final_url}: {e}")
                 else: # Need to make a GET request if HEAD was used initially
                      log.debug(f"Making GET request for length filter: {target_url}")
                      get_resp = self._make_request(target_url, method='GET', allow_redirects=self.follow_redirects_path)
                      if get_resp:
                           content_len = len(get_resp.content)
                           # Update status/type based on GET if different and more informative?
                           # status = get_resp.status_code
                           # content_type = get_resp.headers.get('Content-Type','').lower()
                      else:
                           content_len = -1 # Failed to get length
            elif content_len_str is not None:
                 try: content_len = int(content_len_str)
                 except ValueError: content_len = -1

            # Apply filters *before* classifying
            temp_resp_for_filter = type('obj', (object,), {'status_code': status, 'headers': response.headers, 'url': final_url, 'content': b''})() # Mock response for filter
            # Manually set Content-Length if calculated
            if content_len >= 0: temp_resp_for_filter.headers['Content-Length'] = str(content_len)

            if not self._apply_filters(temp_resp_for_filter):
                 # Close stream response if needed
                 if hasattr(response, 'raw') and hasattr(response.raw, 'release_conn'): response.raw.release_conn()
                 return # Filtered out

            # Classify based on filtered response status/type
            is_likely_dir = status in EXISTENCE_STATUS_CODES and ('html' in content_type or status in {301, 302, 307, 308} or status == 403) and not any(path_segment.lower().endswith(ext) for ext in self.wordlists['extensions'])
            is_likely_file = status in EXISTENCE_STATUS_CODES and not is_likely_dir

            result = None
            display_len = content_len if content_len >= 0 else content_len_str # Show calculated or header length
            if is_likely_dir: log.info(f"[+] Found Directory: {final_url} (Status: {status})"); result = ("dirs", final_url)
            elif is_likely_file: log.info(f"[+] Found File/Endpoint: {final_url} (Status: {status}, Type: {content_type}, Size: {display_len})"); result = ("files", final_url)

            if result:
                with self.lock: self.found_items[result[0]].add(result[1]); self.found_items["endpoints"].add(result[1])

            # Close stream response if needed
            if hasattr(response, 'raw') and hasattr(response.raw, 'release_conn'): response.raw.release_conn()


    def _check_param_on_endpoint(self, endpoint_url, param_name):
        """Checks if adding a parameter changes the response."""
        # (Same logic as v3.0, uses self._make_request)
        log.debug(f"Checking param '{param_name}' on endpoint: {endpoint_url}")
        baseline_resp = self._make_request(endpoint_url, method='GET', allow_redirects=True);
        if baseline_resp is None: return
        baseline_status = baseline_resp.status_code; baseline_len = len(baseline_resp.content)
        test_value = f"test{random.randint(1000,9999)}"; separator = '&' if urlparse(endpoint_url).query else '?'; param_url = f"{endpoint_url}{separator}{param_name}={test_value}"
        param_resp = self._make_request(param_url, method='GET', allow_redirects=True)
        if param_resp is None: return
        param_status = param_resp.status_code; param_len = len(param_resp.content)
        status_diff = param_status != baseline_status; len_diff = abs(param_len - baseline_len) > PARAM_LEN_DIFF_THRESHOLD and baseline_len > 0
        if status_diff or len_diff:
            log.info(f"[+] Potential Parameter Found: '{param_name}' on {endpoint_url} (Status: {baseline_status}->{param_status}, LenDiff: {abs(param_len - baseline_len)})")
            with self.lock:
                 if endpoint_url not in self.found_items["potential_params"]: self.found_items["potential_params"][endpoint_url] = set()
                 self.found_items["potential_params"][endpoint_url].add(param_name); self.found_items["params"].add(param_name)

    def _check_subdomain(self, subdomain):
        """Checks if a subdomain exists and is accessible."""
        # (Same logic as v3.0, uses self._make_request and self.check_ssl)
        target_url = f"{self.target_scheme}://{subdomain}.{self.target_host}"
        log.debug(f"Checking subdomain: {target_url}")
        response = self._make_request(target_url, method='HEAD', allow_redirects=False) # Removed check_ssl override, use session default
        if response is None: response = self._make_request(target_url, method='GET', stream=True, allow_redirects=False) # Removed check_ssl override
        if response is not None and response.status_code < 500:
            # Apply filters to subdomain response? Maybe just status code?
            if self._apply_filters(response):
                 log.info(f"[+] Found Subdomain: {target_url} (Status: {response.status_code})")
                 with self.lock: self.found_items["subdomains"].add(target_url)
            if hasattr(response, 'raw') and hasattr(response.raw, 'release_conn'): response.raw.release_conn()

    # --- Discovery Methods ---
    def discover_dirs_files(self, executor):
        """Uses wordlists to discover directories and files."""
        # (Same logic as v3.0)
        log.info("Starting directory and file enumeration...")
        dir_wordlist = self.wordlists['dirs']; file_wordlist = self.wordlists['files']; extensions = self.wordlists['extensions']
        paths_to_check = set()
        for d in dir_wordlist: paths_to_check.add(d); paths_to_check.add(d + '/')
        for f in file_wordlist: paths_to_check.add(f)
        for d in dir_wordlist:
             for ext in extensions: paths_to_check.add(f"{d}/index{ext}"); paths_to_check.add(f"{d}{ext}")
        log.info(f"Submitting {len(paths_to_check)} paths for checking...")
        futures = [executor.submit(self._check_path, path) for path in paths_to_check]
        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            if processed_count % 250 == 0: log.info(f"    Checked {processed_count}/{len(paths_to_check)} paths...")
            try: future.result()
            except Exception as exc: log.error(f"Path check generated an exception: {exc}")
        log.info("Directory and file enumeration finished.")

    def _analyze_js_file(self, js_url):
        """Fetches a JS file and extracts potential paths."""
        # (Same logic as v3.0)
        log.debug(f"Analyzing JS file: {js_url}")
        response = self._make_request(js_url)
        if response is None or 'javascript' not in response.headers.get('Content-Type', '').lower(): return
        js_content = response.text; found_paths_in_js = set()
        matches = JS_PATH_REGEX.finditer(js_content)
        for match in matches:
            path = match.group(1); path = path.strip().replace('\\/', '/')
            if path.startswith('//'): path = f"{self.target_scheme}:{path}"
            full_url = urljoin(js_url, path); parsed_found = urlparse(full_url)
            if parsed_found.scheme in ['http', 'https'] and parsed_found.netloc == self.target_host:
                 clean_url = parsed_found._replace(fragment='', query='').geturl()
                 if clean_url not in self.found_items["endpoints"]: log.info(f"[+] Found potential endpoint in JS ({os.path.basename(js_url)}): {clean_url}"); found_paths_in_js.add(clean_url)
        matches_rel = JS_RELATIVE_PATH_REGEX.finditer(js_content)
        for match in matches_rel:
            path = match.group(1).strip()
            if not path.startswith('/'): continue
            full_url = urljoin(self.base_url, path); parsed_found = urlparse(full_url)
            if parsed_found.netloc == self.target_host:
                 clean_url = parsed_found._replace(fragment='', query='').geturl()
                 if clean_url not in self.found_items["endpoints"]: log.info(f"[+] Found potential endpoint in JS ({os.path.basename(js_url)}): {clean_url}"); found_paths_in_js.add(clean_url)
        if found_paths_in_js:
            with self.lock: self.found_items["endpoints"].update(found_paths_in_js)

    def discover_endpoints_crawl(self, executor):
        """Crawls the site, finds endpoints/params, and queues JS files for analysis."""
        # (Same logic as v3.0)
        log.info("Starting crawl to discover endpoints, parameters, and JS files...")
        queue = deque([(self.base_url, 0)]); self.processed_urls.add(self.base_url)
        max_crawl_depth = 2; js_analysis_futures = []
        while queue:
            current_url, current_depth = queue.popleft()
            log.info(f"Crawling: {current_url} (Depth: {current_depth})")
            if current_depth >= max_crawl_depth: continue
            # self._extract_params(current_url) # <--- MODIFIED: Commented out this line
            response = self._make_request(current_url)
            if response is None or 'html' not in response.headers.get('Content-Type', '').lower(): continue
            strainer = SoupStrainer(['a', 'form', 'script', 'link', 'iframe', 'frame'])
            try: html_content = response.content.decode(errors='ignore'); soup = BeautifulSoup(html_content, 'lxml', parse_only=strainer)
            except Exception as e: log.warning(f"Failed to parse HTML from {current_url}: {e}"); continue
            found_links_on_page = set(); tags_attrs = [(['a', 'link'], 'href'), (['form'], 'action'), (['script', 'iframe', 'frame'], 'src')]
            for tags, attr in tags_attrs:
                for tag in soup.find_all(tags, {attr: True}):
                    value = tag[attr]
                    if attr == 'href' and value.strip().lower().startswith('javascript:'): continue
                    full_url = urljoin(current_url, value); parsed_link = urlparse(full_url)
                    if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == self.target_host:
                        clean_url = parsed_link._replace(fragment='').geturl()
                        found_links_on_page.add(clean_url)
                        with self.lock: self.found_items["endpoints"].add(clean_url)
                        # Also try extracting parameters from the URL found
                        # if urlparse(clean_url).query:
                        #     self._extract_params(clean_url) # Also maybe call extract here?

                        if tag.name == 'script' and attr == 'src' and clean_url.endswith('.js'):
                             if clean_url not in self.found_items["js_files"]:
                                  log.debug(f"Queueing JS file for analysis: {clean_url}")
                                  with self.lock: self.found_items["js_files"].add(clean_url)
                                  js_analysis_futures.append(executor.submit(self._analyze_js_file, clean_url))
            added_count = 0
            for link in found_links_on_page:
                if link not in self.processed_urls: self.processed_urls.add(link); queue.append((link, current_depth + 1)); added_count +=1
            if added_count > 0: log.info(f"  Added {added_count} new links to crawl queue.")
        log.info("Crawl finished. Waiting for JS analysis tasks...")
        processed_js = 0
        for future in concurrent.futures.as_completed(js_analysis_futures):
             processed_js += 1
             if processed_js % 10 == 0: log.info(f"   Analyzed {processed_js}/{len(js_analysis_futures)} JS files...")
             try: future.result()
             except Exception as exc: log.error(f"JS analysis task generated an exception: {exc}")
        log.info("JS analysis finished.")

    def discover_endpoints_common(self, executor):
        """Checks for common API/admin paths."""
        # (Same logic as v3.0)
        log.info("Checking common API/admin paths...")
        common_paths = set(DEFAULT_API_PATHS + ['admin', 'administrator', 'login', 'dashboard', 'test', 'dev'])
        futures = [executor.submit(self._check_path, path) for path in common_paths]
        for future in concurrent.futures.as_completed(futures):
             try: future.result()
             except Exception as exc: log.error(f"Common path check generated an exception: {exc}")
        log.info("Common path check finished.")

    def discover_endpoints_special_files(self, executor):
        """Checks for robots.txt and sitemap.xml using robust parsing."""
        # (Same logic as v3.0)
        log.info("Checking for robots.txt and sitemap.xml...")
        robots_url = urljoin(self.base_url, '/robots.txt'); log.debug(f"Fetching {robots_url}")
        rp = urllib.robotparser.RobotFileParser(); rp.set_url(robots_url)
        try:
            # Use session's UA by default
            response = self._make_request(robots_url)
            if response and response.status_code == 200:
                 log.info(f"[+] Found: {robots_url}") # Removed semicolon here
                 with self.lock: # Moved 'with' statement to a new line and indented
                     self.found_items["files"].add(robots_url)
                 rp.parse(response.text.splitlines())
                 if rp.entries:
                     for entry in rp.entries:
                         # Accommodate potential changes in robotparser library structure
                         paths = getattr(entry, 'rulelines', [])
                         if not paths and hasattr(entry, 'rules'): # Fallback?
                              paths = entry.rules

                         for rule in paths:
                              # Check rule structure (e.g., is it a RuleLine object or simpler tuple?)
                              rule_path = getattr(rule, 'path', None)
                              if rule_path is None and isinstance(rule, (list, tuple)) and len(rule) > 1: # Heuristic for older structure
                                   rule_path = rule[1] # Assuming path is second element

                              rule_allowance = getattr(rule, 'allowance', None)
                              if rule_allowance is None and isinstance(rule, (list, tuple)) and len(rule) > 0:
                                   rule_allowance = rule[0].lower() == 'allow' # Assuming first element indicates allowance

                              if rule_path and rule_path != '/':
                                   full_path_url = urljoin(self.base_url, rule_path.strip())
                                   if urlparse(full_path_url).netloc == self.target_host:
                                        log.info(f"[+] Found via robots.txt ({'Allow' if rule_allowance else 'Disallow'}): {full_path_url}")
                                        with self.lock: self.found_items["endpoints"].add(full_path_url)
                                        # Maybe extract params here too if needed?
                                        # if urlparse(full_path_url).query:
                                        #     self._extract_params(full_path_url)
            else: log.debug(f"robots.txt not found or not accessible at {robots_url}")
        except AttributeError as ae: log.error(f"Attribute error parsing robots.txt (library structure might differ?): {ae}");
        except Exception as e: log.warning(f"Error processing robots.txt from {robots_url}: {e}")

        # Sitemap processing (similar logic, added param extraction check)
        sitemap_urls_to_check = {urljoin(self.base_url, '/sitemap.xml')}
        processed_sitemaps = set(); max_sitemap_depth = 3; current_depth = 0
        while sitemap_urls_to_check and current_depth < max_sitemap_depth:
            current_sitemap_url = sitemap_urls_to_check.pop()
            if current_sitemap_url in processed_sitemaps: continue
            processed_sitemaps.add(current_sitemap_url); log.debug(f"Fetching sitemap: {current_sitemap_url}")
            response = self._make_request(current_sitemap_url)
            if not (response and response.status_code == 200 and 'xml' in response.headers.get('Content-Type','').lower()): log.debug(f"Sitemap not found or not XML at {current_sitemap_url}"); continue
            log.info(f"[+] Found Sitemap: {current_sitemap_url}");
            with self.lock: self.found_items["files"].add(current_sitemap_url)
            try:
                xml_content = response.content; root = ET.fromstring(xml_content)
                # Define namespaces - adjust if your sitemaps use different ones
                namespaces = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                # Helper to find elements with namespace handling
                def find_all_ns(element, tag):
                    try:
                         # Try finding with the common namespace first
                         found = element.findall(f'.//sm:{tag}', namespaces)
                         if found: return found
                         # If not found, try without namespace (common for simpler sitemaps)
                         return element.findall(f'.//{tag}')
                    except Exception as find_err: # Catch potential errors during findall
                         log.warning(f"Error finding tag '{tag}' in sitemap {current_sitemap_url}: {find_err}")
                         return []


                sitemap_index_locs = find_all_ns(root, 'sitemap')
                if sitemap_index_locs:
                     log.info(f"  -> Found sitemap index file, parsing nested sitemaps...")
                     for sitemap_tag in sitemap_index_locs:
                          loc_tag_list = find_all_ns(sitemap_tag, 'loc') # Use list directly
                          if loc_tag_list and loc_tag_list[0].text:
                               nested_sitemap_url = loc_tag_list[0].text.strip()
                               if nested_sitemap_url not in processed_sitemaps: sitemap_urls_to_check.add(nested_sitemap_url)
                else:
                     url_locs = find_all_ns(root, 'url')
                     for url_tag in url_locs:
                          loc_tag_list = find_all_ns(url_tag, 'loc') # Use list directly
                          if loc_tag_list and loc_tag_list[0].text:
                               loc_url = loc_tag_list[0].text.strip(); parsed_loc = urlparse(loc_url)
                               if parsed_loc.scheme in ['http', 'https'] and parsed_loc.netloc == self.target_host:
                                   log.info(f"[+] Found via sitemap.xml: {loc_url}");
                                   with self.lock: self.found_items["endpoints"].add(loc_url);
                                   # Call param extraction if the method existed and was desired here
                                   # if parsed_loc.query:
                                   #     self._extract_params(loc_url)
            except ET.ParseError as e_xml: log.warning(f"Could not parse XML sitemap {current_sitemap_url}: {e_xml}")
            except Exception as e: log.warning(f"Error processing sitemap {current_sitemap_url}: {e}")
            if sitemap_index_locs: current_depth += 1 # Increment depth only for index files to avoid infinite loops
        log.info("Special file check finished.")

    def discover_params_brute(self, executor):
        """Brute-forces common parameters on discovered endpoints."""
        # (Same logic as v3.0)
        log.info("Starting parameter brute-force...")
        endpoints_to_test = set()
        with self.lock:
            # Filter out common static file extensions before testing for params
            endpoints_to_test.update(self.found_items["endpoints"])
            endpoints_to_test = {ep for ep in endpoints_to_test if not any(ep.lower().endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map'])}
        if not endpoints_to_test: log.warning("No suitable endpoints found to brute-force parameters against."); return
        param_wordlist = self.wordlists['params']
        log.info(f"Submitting {len(endpoints_to_test) * len(param_wordlist)} parameter checks...")
        futures = [executor.submit(self._check_param_on_endpoint, endpoint, param) for endpoint in endpoints_to_test for param in param_wordlist]
        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            if processed_count % 250 == 0: log.info(f"    Checked {processed_count}/{len(futures)} parameters...")
            try: future.result()
            except Exception as exc: log.error(f"Parameter check generated an exception: {exc}")
        log.info("Parameter brute-force finished.")

    def discover_subdomains(self, executor):
        """Brute-forces common subdomains."""
        # (Same logic as v3.0)
        log.info("Starting subdomain enumeration...")
        subdomain_wordlist = self.wordlists['subdomains']
        log.info(f"Submitting {len(subdomain_wordlist)} subdomain checks...")
        futures = [executor.submit(self._check_subdomain, sub) for sub in subdomain_wordlist]
        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            if processed_count % 50 == 0: log.info(f"    Checked {processed_count}/{len(subdomain_wordlist)} subdomains...")
            try: future.result()
            except Exception as exc: log.error(f"Subdomain check generated an exception: {exc}")
        log.info("Subdomain enumeration finished.")


    def run(self):
        """Runs the selected reconnaissance modes."""
        log.info(f"Starting ReconRaptor v{__version__} scan on {self.base_url}")
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            # Submit tasks based on modes, handling dependencies
            endpoint_discovery_submitted = False
            endpoint_tasks = []

            # Group endpoint-related tasks
            if self.modes.get('endpoints') or self.modes.get('params') or self.modes.get('brute_params'):
                 log.info("Queueing endpoint discovery tasks...")
                 # Run crawl first as it might find JS/links needed by other tasks or param brute-force
                 # Check if crawling is disabled
                 if not self.modes.get('no_crawl'):
                      # Submit crawl and let it run; JS analysis happens within it
                      endpoint_tasks.append(executor.submit(self.discover_endpoints_crawl, executor))
                 else:
                      log.info("Skipping crawl based on --no-crawl flag.")

                 # Submit other endpoint tasks concurrently now
                 if not self.modes.get('no_common_paths'): # Check flag
                      endpoint_tasks.append(executor.submit(self.discover_endpoints_common, executor))
                 # Combine special file checks into one task if desired, or keep separate
                 if not self.modes.get('no_robots') or not self.modes.get('no_sitemap'):
                      endpoint_tasks.append(executor.submit(self.discover_endpoints_special_files, executor))
                 endpoint_discovery_submitted = True


            dir_file_task = None
            if self.modes.get('dirs') or self.modes.get('files'):
                 dir_file_task = executor.submit(self.discover_dirs_files, executor)

            subdomain_task = None
            if self.modes.get('subdomains'):
                 subdomain_task = executor.submit(self.discover_subdomains, executor)

            # Wait for initial endpoint discovery tasks (crawl, common, special files) to complete
            # before starting parameter brute-force, as it relies on discovered endpoints.
            if endpoint_tasks:
                 log.info("Waiting for endpoint discovery tasks (crawl/common/special files)...")
                 concurrent.futures.wait(endpoint_tasks)
                 log.info("Endpoint discovery tasks finished.")
                 # Check for exceptions in completed endpoint tasks
                 for f in endpoint_tasks:
                      if f.exception(): log.error(f"Endpoint discovery task failed: {f.exception()}", exc_info=f.exception())


            # Run param brute-force if requested (after endpoint discovery is done)
            param_brute_task = None
            if self.modes.get('brute_params'):
                 # Submit the task now that endpoints should be populated
                 param_brute_task = executor.submit(self.discover_params_brute, executor)

            # Wait for remaining tasks (dirs/files, subdomains, and potentially param_brute)
            remaining_tasks = [t for t in [dir_file_task, subdomain_task, param_brute_task] if t is not None]
            if remaining_tasks:
                 log.info("Waiting for Dir/File/Subdomain/ParamBrute tasks...")
                 concurrent.futures.wait(remaining_tasks)
                 log.info("All remaining discovery tasks finished.")
                 # Check for exceptions in these tasks
                 for f in remaining_tasks:
                      if f.exception(): log.error(f"Discovery task failed: {f.exception()}", exc_info=f.exception())


        end_time = time.time()
        log.info(f"Recon scan finished in {end_time - start_time:.2f} seconds.")


    def report(self, json_output_path=None):
        """Prints and optionally saves the report."""
        # (Same logic as v3.0)
        report_data = {"target": self.base_url, "scan_modes": [k for k, v in self.modes.items() if v and not k.startswith('no_')], "results": {}} # Filter out 'no_' flags

        # Populate results based on modes that were actually run and have items
        if self.modes.get('dirs'): report_data["results"]["dirs"] = sorted(list(self.found_items.get("dirs", set())))
        if self.modes.get('files'): report_data["results"]["files"] = sorted(list(self.found_items.get("files", set())))
        if self.modes.get('endpoints'):
             report_data["results"]["endpoints"] = sorted(list(self.found_items.get("endpoints", set())))
             # Only include JS files if endpoint discovery (specifically crawl/JS analysis) was run
             if not self.modes.get('no_crawl') and not self.modes.get('no_js_analysis'):
                  report_data["results"]["js_files"] = sorted(list(self.found_items.get("js_files", set())))

        if self.modes.get('subdomains'): report_data["results"]["subdomains"] = sorted(list(self.found_items.get("subdomains", set())))

        # Parameter results depend on params or brute_params modes
        if self.modes.get('params') or self.modes.get('brute_params'):
             # Parameters found via brute-force or potentially extracted (if _extract_params existed)
             report_data["results"]["parameters_found"] = sorted(list(self.found_items.get('params', set())))
             # Parameters found by checking response difference (potential_params)
             report_data["results"]["potential_parameters_on_endpoints"] = {k: sorted(list(v)) for k, v in self.found_items.get('potential_params', {}).items()}
             # URLs that originally contained parameters (if _extract_params existed)
             # report_data["results"]["urls_containing_parameters"] = sorted(list(self.found_items.get('urls_with_params', set())))


        print("\n--- ReconRaptor Report ---"); print(f"Target: {self.base_url}\n")
        # Iterate through the keys we potentially added to report_data["results"]
        report_keys_ordered = ["dirs", "files", "endpoints", "js_files", "subdomains", "parameters_found", "potential_parameters_on_endpoints"] #, "urls_containing_parameters"]
        for key in report_keys_ordered:
            if key not in report_data["results"]: continue # Skip if mode wasn't run or no results found

            items = report_data["results"][key]
            # Standard handling for most list-based results
            if isinstance(items, list):
                 title = key.replace("_", " ").capitalize()
                 print(f"[*] Found {title} ({len(items)}):")
                 if items:
                     for item in items: print(f"  - {item}")
                 else: print("    None found.")
            # Special handling for potential parameters dictionary
            elif key == "potential_parameters_on_endpoints" and isinstance(items, dict):
                  title = key.replace("_", " ").capitalize()
                  total_potential = sum(len(v) for v in items.values())
                  print(f"[*] {title} ({total_potential} instances):")
                  if items:
                       # Sort endpoints for consistent output
                       for endpoint, params_found in sorted(items.items()):
                            print(f"  - {endpoint} -> [{', '.join(params_found)}]")
                  else: print("    None found (or brute-force mode not run).")
            # Handling for the single list of parameters found
            elif key == "parameters_found" and isinstance(items, list):
                 title = key.replace("_", " ").capitalize()
                 print(f"[*] {title} ({len(items)}):")
                 if items: print(f"    {', '.join(items)}")
                 else: print("    None found.")

            if items or isinstance(items, dict): # Add separator only if section had content
                 print("-" * 20)

        print("--- End of Report ---")

        # JSON Output
        if json_output_path:
            log.info(f"Saving report to JSON file: {json_output_path}")
            try:
                # Use the filtered report_data for JSON output
                with open(json_output_path, 'w', encoding='utf-8') as f: json.dump(report_data, f, indent=4)
                log.info("Report saved successfully.")
            except IOError as e: log.error(f"Failed to write JSON report to {json_output_path}: {e}")
            except Exception as e: log.error(f"Unexpected error saving JSON report: {e}")

    def close(self):
        """Cleans up resources."""
        if self.session: self.session.close()
        log.info("ReconRaptor finished.")


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"ReconRaptor v{__version__} - Website Reconnaissance Tool. Use Responsibly!",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Input/Output Arguments
    parser.add_argument("url", help="The target base URL to scan (e.g., https://example.com)")
    parser.add_argument("-o", "--output-log", help="File to write detailed scan logs to")
    parser.add_argument("--json-out", help="File path to save findings in JSON format")

    # Scan Control Arguments
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS_DEFAULT, help="Number of concurrent workers")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay in seconds between requests")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Custom User-Agent string")
    parser.add_argument("-H", "--header", action='append', help="Add custom header (e.g., 'Cookie: session=123'). Can use multiple times.")
    parser.add_argument("-b", "--cookie", action='append', help="Add custom cookie (e.g., 'user=admin'). Can use multiple times.")
    parser.add_argument("--follow-redirects", action='store_true', help="Follow redirects during directory/file checks")
    parser.add_argument("-k", "--insecure", action='store_true', help="Ignore SSL certificate errors")

    # Mode Selection Arguments
    mode_group = parser.add_argument_group('Discovery Modes (Default: All if none selected)')
    mode_group.add_argument("--dirs", action="store_true", help="Scan for directories")
    mode_group.add_argument("--files", action="store_true", help="Scan for files")
    mode_group.add_argument("--endpoints", action="store_true", help="Scan for endpoints (crawl, common, special files, JS analysis)")
    mode_group.add_argument("--params", action="store_true", help="Discover parameters found in URLs (requires --endpoints or default; currently limited due to missing _extract_params)")
    mode_group.add_argument("--brute-params", action="store_true", help="Brute-force common parameters on discovered endpoints (requires --endpoints or default)")
    mode_group.add_argument("--subdomains", action="store_true", help="Scan for subdomains")

    # Endpoint Discovery Fine-tuning (only relevant if --endpoints or default)
    ep_filter_group = parser.add_argument_group('Endpoint Discovery Tuning (Requires --endpoints or default)')
    ep_filter_group.add_argument("--no-crawl", action="store_true", help="Disable crawling for endpoint discovery")
    ep_filter_group.add_argument("--no-js-analysis", action="store_true", help="Disable JS analysis for endpoint discovery (part of crawl)")
    ep_filter_group.add_argument("--no-robots", action="store_true", help="Disable checking robots.txt for endpoints")
    ep_filter_group.add_argument("--no-sitemap", action="store_true", help="Disable checking sitemap.xml for endpoints")
    ep_filter_group.add_argument("--no-common-paths", action="store_true", help="Disable checking common API/admin paths")


    # Wordlist Arguments
    wordlist_group = parser.add_argument_group('Wordlist Options')
    wordlist_group.add_argument("-wD", "--wordlist-dirs", help="Path to directory wordlist file")
    wordlist_group.add_argument("-wF", "--wordlist-files", help="Path to file wordlist file")
    wordlist_group.add_argument("-wE", "--wordlist-extensions", help="Path to file extension wordlist file (include '.' e.g., .php)")
    wordlist_group.add_argument("-wP", "--wordlist-params", help="Path to parameter name wordlist file")
    wordlist_group.add_argument("-wS", "--wordlist-subdomains", help="Path to subdomain wordlist file")

    # Filtering Arguments
    filter_group = parser.add_argument_group('Result Filtering Options (for Dirs/Files/Subdomains)')
    filter_group.add_argument("--include-status", help="Comma-separated list of status codes to include (e.g., 200,403)")
    filter_group.add_argument("--exclude-status", help="Comma-separated list of status codes to exclude (e.g., 404,400)")
    filter_group.add_argument("--min-length", type=int, help="Minimum content length to include")
    filter_group.add_argument("--max-length", type=int, help="Maximum content length to include (e.g., 0 to hide 0-length)")

    # Logging Arguments
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument("-v", "--verbose", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.INFO, help="Enable verbose (debug) logging")
    log_group.add_argument("-q", "--quiet", action="store_const", dest="loglevel", const=logging.WARNING, help="Suppress informational messages (show warnings/errors only)")

    args = parser.parse_args()

    # --- Configure Logging ---
    log.setLevel(args.loglevel)
    if args.output_log:
        try:
            # Ensure directory exists for log file if specified in a path
            log_dir = os.path.dirname(args.output_log)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)

            file_handler = logging.FileHandler(args.output_log, mode='w')
            file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(threadName)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_formatter); log.addHandler(file_handler)
            log.info(f"Logging detailed output to: {args.output_log}")
        except OSError as e: log.error(f"Failed to create directory for log file {args.output_log}: {e}"); sys.exit(1)
        except Exception as e: log.error(f"Failed to open log file {args.output_log}: {e}"); sys.exit(1)
    # --- End Logging Config ---

    # Process Headers & Cookies
    custom_headers = {}
    if args.header:
        for h in args.header:
            parsed_h = parse_header(h)
            if parsed_h: custom_headers[parsed_h[0]] = parsed_h[1]
    custom_cookies = {}
    if args.cookie:
        for c in args.cookie:
            parsed_c = parse_cookie(c)
            if parsed_c: custom_cookies[parsed_c[0]] = parsed_c[1]

    # Process Filters
    filters = {
        'include_status': set(int(s.strip()) for s in args.include_status.split(',')) if args.include_status else None,
        'exclude_status': set(int(s.strip()) for s in args.exclude_status.split(',')) if args.exclude_status else None,
        'min_length': args.min_length,
        'max_length': args.max_length,
    }

    # Determine modes to run
    run_modes = {
        'dirs': args.dirs, 'files': args.files, 'endpoints': args.endpoints,
        'params': args.params, 'brute_params': args.brute_params, 'subdomains': args.subdomains,
        # Add endpoint sub-modes for control within run()
        'no_crawl': args.no_crawl, 'no_js_analysis': args.no_js_analysis,
        'no_robots': args.no_robots, 'no_sitemap': args.no_sitemap,
        'no_common_paths': args.no_common_paths
    }
    selected_modes = [k for k, v in run_modes.items() if v and not k.startswith('no_')]
    if not selected_modes:
         log.info("No specific mode selected, running all discovery modes.")
         # Set all major modes to True, respect 'no_' flags
         run_modes = {k: True for k in ['dirs', 'files', 'endpoints', 'params', 'brute_params', 'subdomains']}
         run_modes.update({ # Keep explicit 'no_' flags if user set them
            'no_crawl': args.no_crawl, 'no_js_analysis': args.no_js_analysis,
            'no_robots': args.no_robots, 'no_sitemap': args.no_sitemap,
            'no_common_paths': args.no_common_paths
         })
    else:
         log.info(f"Running selected modes: {selected_modes}")
         # Ensure endpoint mode is enabled if param discovery/brute is selected
         if (run_modes['params'] or run_modes['brute_params']) and not run_modes['endpoints']:
              log.info("Parameter discovery/brute-force requires endpoint discovery, enabling endpoint mode.")
              run_modes['endpoints'] = True # Force enable endpoints
              # Also potentially warn user if crawl is disabled but params are requested?

    # Prepare wordlist paths dictionary
    wordlist_paths = {
        'dirs': args.wordlist_dirs, 'files': args.wordlist_files,
        'extensions': args.wordlist_extensions, 'params': args.wordlist_params,
        'subdomains': args.wordlist_subdomains
    }

    # Initialize and run scanner
    scanner = None
    try:
        scanner = ReconRunner( # <--- MODIFIED: Changed ReconRaptor to ReconRunner
            target_url=args.url, modes=run_modes, wordlist_paths=wordlist_paths,
            workers=args.workers, delay=args.delay, user_agent=args.user_agent, timeout=args.timeout,
            headers=custom_headers, cookies=custom_cookies, insecure=args.insecure,
            follow_redirects=args.follow_redirects, filters=filters
        )
        scanner.run()
        scanner.report(args.json_out)

    except ValueError as ve: log.critical(f"Initialization Error: {ve}"); sys.exit(1)
    except KeyboardInterrupt: log.warning("\nScan interrupted by user."); print("\nScan aborted.", file=sys.stderr); sys.exit(1)
    except Exception as e:
        log.critical(f"An unexpected critical error occurred: {e}", exc_info=True) # Log traceback for critical errors
        sys.exit(1)
    finally:
         if scanner: scanner.close()