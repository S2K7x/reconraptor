# ReconRaptor v4.0

**A Flexible Web Reconnaissance Tool**

## ⚠️ Disclaimer ⚠️

**This tool is intended for educational purposes and authorized security testing ONLY.** Running this scanner against websites without explicit, written permission from the owner is **illegal and unethical**. The developers assume no liability and are not responsible for any misuse or damage caused by this tool. **Use responsibly.**

## Description

ReconRaptor is a Python-based reconnaissance tool designed to map out web application structures and discover potential points of interest. It performs various checks including directory/file enumeration, endpoint discovery (via crawling, common paths, `robots.txt`, `sitemap.xml`, and JavaScript analysis), parameter discovery (extraction and optional brute-forcing), and subdomain enumeration. It offers flexibility through custom wordlists, result filtering, and request customization options.

## Features

* **Modular Scanning:** Run all recon modes or select specific ones (directories, files, endpoints, parameters, brute-force parameters, subdomains).
* **Directory/File Enumeration:** Brute-forces common directories and files using wordlists. Supports custom extensions.
* **Endpoint Discovery:**
    * Crawls the target site (limited depth) to find links, forms, scripts, etc.
    * Checks for common paths (`/api`, `/admin`, etc.).
    * Parses `robots.txt` using `urllib.robotparser`.
    * Parses `sitemap.xml` (including basic index files) using `xml.etree.ElementTree`.
    * Analyzes discovered JavaScript files for potential paths using regular expressions.
    * Allows disabling specific discovery methods (e.g., `--no-crawl`).
* **Parameter Discovery:**
    * Extracts parameters found in URLs during crawling and sitemap parsing.
    * Optional brute-forcing (`--brute-params`) of common parameter names against discovered endpoints.
* **Subdomain Enumeration:** Optional brute-forcing (`--subdomains`) of common subdomain names.
* **Customization:**
    * Supports custom wordlists for directories, files, extensions, parameters, and subdomains.
    * Allows adding custom HTTP headers (`-H`) and cookies (`-b`).
    * Option to follow redirects during path checks (`--follow-redirects`).
    * Option to ignore SSL errors (`-k`/`--insecure`).
* **Filtering:** Filter directory, file, and subdomain results based on status codes (`--include-status`, `--exclude-status`) and content length (`--min-length`, `--max-length`).
* **Concurrency:** Uses `ThreadPoolExecutor` to speed up checks.
* **Rate Limiting:** Optional delay (`--delay`) between requests.
* **Output:** Console summary and optional detailed JSON output (`--json-out`).
* **Logging:** Configurable logging levels (`-v`, `-q`) and optional logging to file (`-o`).

## Requirements

* Python 3.7+
* Python libraries listed in `requirements.txt`:
    * `requests`
    * `beautifulsoup4`
    * `urllib3`

## Installation

1.  **Clone the repository (or download the script):**
    ```bash
    # git clone <your-repo-url>
    # cd recon-raptor
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
python recon_raptor.py <target_url> [options]
```

**Required Argument:**

* `url`: The target base URL for the scan (e.g., `https://example.com`).

**Common Options:**

* **Mode Selection (Default: All)**
    * `--dirs`: Only scan for directories.
    * `--files`: Only scan for files.
    * `--endpoints`: Only scan for endpoints.
    * `--params`: Only discover parameters found in URLs (requires endpoint scan).
    * `--brute-params`: Only brute-force parameters (requires endpoint scan).
    * `--subdomains`: Only scan for subdomains.
* **Endpoint Tuning (If `endpoints` mode is active)**
    * `--no-crawl`: Disable crawling.
    * `--no-js-analysis`: Disable analyzing JS files.
    * `--no-robots`: Disable checking `robots.txt`.
    * `--no-sitemap`: Disable checking `sitemap.xml`.
    * `--no-common-paths`: Disable checking common API/admin paths.
* **Wordlists**
    * `-wD FILE`, `--wordlist-dirs FILE`: Path to directory wordlist.
    * `-wF FILE`, `--wordlist-files FILE`: Path to file wordlist.
    * `-wE FILE`, `--wordlist-extensions FILE`: Path to extension wordlist.
    * `-wP FILE`, `--wordlist-params FILE`: Path to parameter wordlist.
    * `-wS FILE`, `--wordlist-subdomains FILE`: Path to subdomain wordlist.
* **Scan Control**
    * `-d DEPTH`, `--depth DEPTH`: Max crawl depth (Default: 2).
    * `-w WORKERS`, `--workers WORKERS`: Number of concurrent workers (Default: 25).
    * `--delay DELAY`: Delay between requests (seconds, Default: 0).
    * `--timeout TIMEOUT`: Request timeout (seconds, Default: 10).
    * `--user-agent USER_AGENT`: Custom User-Agent.
    * `-H HEADER`, `--header HEADER`: Add custom header ('Name: Value'). Use multiple times.
    * `-b COOKIE`, `--cookie COOKIE`: Add custom cookie ('name=value'). Use multiple times.
    * `--follow-redirects`: Follow redirects during dir/file checks.
    * `-k`, `--insecure`: Ignore SSL certificate errors.
* **Filtering**
    * `--include-status CODES`: Comma-separated status codes to include (e.g., `200,403`).
    * `--exclude-status CODES`: Comma-separated status codes to exclude (e.g., `404`).
    * `--min-length LEN`: Minimum content length to include.
    * `--max-length LEN`: Maximum content length to include.
* **Output & Logging**
    * `--json-out FILE`: Save results to a JSON file.
    * `-o FILE`, `--output-log FILE`: File to write detailed logs to.
    * `-v`, `--verbose`: Enable debug logging.
    * `-q`, `--quiet`: Suppress info messages (show warnings/errors).

**Examples:**

1.  **Full Recon Scan (Default Modes):**
    ```bash
    python recon_raptor.py [https://example.com](https://example.com) -v -o scan.log --json-out results.json
    ```

2.  **Directory & File Scan with Custom Wordlists & Filtering:**
    ```bash
    python recon_raptor.py [https://example.com](https://example.com) --dirs --files -wD common_dirs.txt -wF common_files.txt --include-status 200,403 --min-length 10
    ```

3.  **Endpoint Discovery (No Crawl) & Subdomain Scan:**
    ```bash
    python recon_raptor.py [https://example.com](https://example.com) --endpoints --no-crawl --subdomains -wS subdomains.txt
    ```

4.  **Parameter Brute-Force with Custom Headers & Delay:**
    ```bash
    python recon_raptor.py [https://api.example.com](https://api.example.com) --brute-params -H "Authorization: Bearer ..." -b "session=xyz" --delay 0.1
    ```

## Output Interpretation

* The console output shows findings categorized by type (Directories, Files, Endpoints, Subdomains, Parameters).
* Parameter findings include parameters extracted from URLs and potential parameters found via brute-forcing (distinguished in the report).
* The JSON output (`--json-out`) provides a structured representation of all findings.

## Limitations

* **JS Analysis:** Relies on regular expressions, which can miss dynamically generated endpoints or produce false positives.
* **Parameter Brute-Force:** Detection is basic (status/length changes) and may not identify all valid parameters or their impact.
* **Subdomain Enumeration:** Basic check; doesn't robustly handle wildcard DNS.
* **Context Analysis:** The tool does not perform context analysis like the XSS scanner; it focuses on discovery.
* **Authentication:** No built-in support for handling complex login flows beyond passing cookies/headers.
* **Performance:** Can be slow on large sites or with large wordlists, especially with delays or low worker counts.

## License

(Specify your chosen license here, e.g., MIT License)

```
[Link to LICENSE file or full license text]
```

## Contributing

(Optional: Add guidelines if you want others to contribute)

```
Contributions are welcome! Please read CONTRIBUTING.md for details.
