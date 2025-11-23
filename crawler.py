#!/usr/bin/python3
# This web app provides a WARC viewer and a web archiver

import re
import os
import sys
import time
import base64
import shutil
import sqlite3
import requests
import threading
import traceback
import configparser
import subprocess
import logging
import hashlib
from io import BytesIO
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
from flask import Flask, render_template, request, jsonify, redirect, url_for, render_template_string, session, flash
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter
from internetarchive import upload
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError
from functools import wraps

# Selenium imports for Advanced mode
try:
	from selenium import webdriver
	from selenium.webdriver.chrome.options import Options as ChromeOptions
	from selenium.webdriver.chrome.service import Service as ChromeService
	from selenium.webdriver.common.by import By
	from selenium.webdriver.support.ui import WebDriverWait
	from selenium.webdriver.support import expected_conditions as EC
	from selenium.common.exceptions import TimeoutException, WebDriverException
	SELENIUM_AVAILABLE = True
except ImportError:
	SELENIUM_AVAILABLE = False

app = Flask(__name__)
cfg = None

# Authentication functions
def hash_password(password):
	"""Hash a password using SHA256"""
	return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, stored_hash):
	"""Verify a password against its stored hash"""
	return hash_password(password) == stored_hash

def login_required(f):
	"""Decorator to require authentication for routes"""
	@wraps(f)
	def decorated_function(*args, **kwargs):
		# From localhost
		if request.remote_addr in ('127.0.0.1', '::1'):
			return f(*args, **kwargs)

		# Not authenticated
		if not session.get('authenticated'):
			return redirect(url_for('login'))

		# Authenticated
		return f(*args, **kwargs)
	return decorated_function

def check_authentication():
	"""Check if user is authenticated and session is still valid"""
	if not session.get('authenticated'):
		return False

	# Check if session has expired
	login_time = session.get('login_time')
	if login_time:
		login_datetime = datetime.fromisoformat(login_time)
		if datetime.now() - login_datetime > timedelta(days=int(cfg.get('general', 'session_days'))):
			session.clear()
			return False

	return True

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
	"""Handle user login"""
	if request.method == 'POST':
		password = request.form.get('password')
		if password:
			stored_hash = cfg.get('general', 'password')
			if verify_password(password, stored_hash):
				session['authenticated'] = True
				session['login_time'] = datetime.now().isoformat()
				next_page = request.args.get('next')
				return redirect(next_page) if next_page else redirect(url_for('index'))
			else:
				flash('Invalid password', 'error')
		else:
			flash('Password is required', 'error')
	return render_template('login.html')

def make_http_request_with_retry(method, url, logger=None, **kwargs):
	"""
	Make an HTTP request with retry logic for temporary failures.

	Args:
		method (str): HTTP method ('get', 'head', 'post', etc.)
		url (str): URL to request
		logger: Logger instance for logging retry attempts and failures
		**kwargs: Additional arguments to pass to requests method

	Returns:
		requests.Response: Response object if successful

	Raises:
		RequestException: If all retries are exhausted
	"""
	# Get the appropriate requests method
	request_method = getattr(requests, method.lower())

	# Get retry configuration from config
	max_retries = int(cfg.get('connections', 'max_retries'))
	base_delay = int(cfg.get('connections', 'base_delay'))
	max_delay = int(cfg.get('connections', 'max_delay'))

	# Special handling for 429 (Too Many Requests)
	last_429_time = None
	rate_limit_retry_duration = 60  # 1 minute for 429 errors

	for attempt in range(max_retries + 1):  # +1 for initial attempt
		try:
			response = request_method(url, **kwargs)

			# Check for 429 status code
			if response.status_code == 429:
				current_time = time.time()

				# If this is the first 429 or enough time has passed since last 429
				if last_429_time is None or (current_time - last_429_time) >= rate_limit_retry_duration:
					last_429_time = current_time
					if attempt < max_retries:
						# Wait 10 seconds before retrying 429
						time.sleep(10)
						continue

				# If we've been getting 429s for too long, give up
				if (current_time - last_429_time) > rate_limit_retry_duration:
					if logger:
						logger.log(f"Rate limited (429) for {url} for too long, giving up after {attempt + 1} attempts", "WARN")
					response.raise_for_status()

			# For other temporary errors, check if we should retry
			elif response.status_code >= 500 or response.status_code == 408:
				if attempt < max_retries:
					# Calculate exponential backoff delay
					delay = min(base_delay * (2 ** attempt), max_delay)
					time.sleep(delay)
					continue
				else:
					if logger:
						logger.log(f"HTTP error {response.status_code} for {url}, max retries ({max_retries}) exceeded, giving up", "WARN")
					response.raise_for_status()

			# Success or permanent error (4xx except 408, 429)
			return response

		except (ConnectionError, Timeout) as e:
			# Network-related errors - always retry
			if attempt < max_retries:
				delay = min(base_delay * (2 ** attempt), max_delay)
				time.sleep(delay)
				continue
			else:
				if logger:
					logger.log(f"Network error ({type(e).__name__}) for {url}, max retries ({max_retries}) exceeded, giving up", "WARN")
				raise

		except HTTPError as e:
			# HTTP errors that aren't handled above
			if attempt < max_retries and e.response.status_code >= 500:
				delay = min(base_delay * (2 ** attempt), max_delay)
				time.sleep(delay)
				continue
			else:
				if logger:
					logger.log(f"HTTP error {e.response.status_code} for {url}, giving up", "WARN")
				raise

		except RequestException as e:
			# Other request exceptions - retry once
			if attempt < max_retries:
				delay = min(base_delay * (2 ** attempt), max_delay)
				time.sleep(delay)
				continue
			else:
				if logger:
					logger.log(f"Request error ({type(e).__name__}) for {url}, max retries ({max_retries}) exceeded, giving up", "WARN")
				raise

	# This should never be reached, but just in case
	if logger:
		logger.log(f"All retries exhausted for {method.upper()} {url}", "WARN")
	raise RequestException(f"All retries exhausted for {method.upper()} {url}")

def load_config(config_file=None):
	"""
	Load configuration from crawler.cfg file.

	Args:
		config_file (str, optional): Path to config file. If None, uses default location.

	Returns:
		configparser.ConfigParser: Loaded configuration object
	"""
	global cfg

	cfg = configparser.ConfigParser()

	# Use provided config file or default location
	if config_file is None:
		config_file = os.path.join(os.path.dirname(__file__), 'crawler.cfg')

	# Load config file
	try:
		cfg.read(config_file)
		for section in cfg.sections():
			for key in cfg[section]:
				value = cfg[section][key]
				if isinstance(value, str) and value.startswith('"') and value.endswith('"'):
					cfg[section][key] = value[1:-1] # Strip quotes
	except Exception as e:
		print(f"Configuration file {config_file} could not be loaded: {e}", file=sys.stderr)
		quit(1)

	return cfg

def create_webdriver():
	"""
	Create and configure a Chrome WebDriver for Selenium-based crawling.

	Returns:
		webdriver.Chrome: Configured Chrome WebDriver instance
	"""
	if not SELENIUM_AVAILABLE:
		raise WebDriverException("Selenium is not available. Please install selenium package.")

	chrome_options = ChromeOptions()
	chrome_options.add_argument('--headless')
	chrome_options.add_argument('--no-sandbox')
	chrome_options.add_argument('--disable-dev-shm-usage')
	chrome_options.add_argument('--disable-gpu')
	chrome_options.add_argument('--disable-extensions')
	chrome_options.add_argument('--disable-plugins')
	chrome_options.add_argument('--disable-images')
	chrome_options.add_argument(f'--user-agent={cfg.get("advanced", "chrome_user_agent")}')

	# Try to create WebDriver
	try:
		driver = webdriver.Chrome(options=chrome_options)
		driver.set_page_load_timeout(int(cfg.get('connections', 'timeout')))  # Use config timeout
		return driver
	except Exception as e:
		raise WebDriverException(f"Failed to create WebDriver: {str(e)}")

class CrawlLogger:
	"""
	A logging class that writes crawl progress and information to the log.
	"""

	def __init__(self, log_file_path):
		"""
		Initialize the logger.

		Args:
			log_file_path (str): Path to the log file
		"""
		self.log_file_path = log_file_path
		self.lock = threading.Lock()

		# Create log file and write initial header
		with open(self.log_file_path, 'w', encoding='utf-8') as f:
			f.write(f"=== Web Crawler Log ===\n")
			f.write(f"Created on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
			f.write(f"Log file: {log_file_path}\n\n")

	def log(self, message, level="INFO"):
		"""
		Log a message with timestamp and level.

		Args:
			message (str): The message to log
			level (str): Log level (INFO, WARN, ERROR, DEBUG)
		"""
		if str(cfg.get("general", "debug")).lower != "true" and str(level).lower() == "debug":
			return

		timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		log_entry = f"[{timestamp}] [{level}] {message}\n"

		with self.lock:
			with open(self.log_file_path, 'a', encoding='utf-8') as f:
				f.write(log_entry)
				f.flush()  # Ensure immediate write

	def log_crawl_start(self, url, mode, max_size, niceness, restrictpage):
		"""
		Log the start of a crawl operation.

		Args:
			url (str): Starting URL
			mode (str): Crawl mode
			max_size (int): Maximum file size
			niceness (bool): Whether to be nice (add delays)
			restrictpage (bool): Whether to restrict to same page
		"""
		self.log(f"Starting crawl of: {url}")
		self.log(f"Crawl mode: {mode}")
		self.log(f"Max file size: {max_size} bytes")
		self.log(f"Be nice (delays): {niceness}")
		self.log(f"Limit to same page: {restrictpage}")
		self.log("=" * 50)

	def log_url_crawl(self, url, status_code, content_type, content_length, file_size=None):
		"""
		Log the crawling of a specific URL.

		Args:
			url (str): The URL being crawled
			status_code (int): HTTP status code
			content_type (str): Content type of the response
			content_length (str): Content length from headers
			file_size (int): Actual file size saved (optional)
		"""
		size_info = f" (saved: {file_size} bytes)" if file_size else ""
		self.log(f"Crawled: {url} - Status: {status_code}, Type: {content_type}, Size: {content_length}{size_info}")

	def log_url_skip(self, url, reason):
		"""
		Log when a URL is skipped.

		Args:
			url (str): The URL being skipped
			reason (str): Reason for skipping
		"""
		self.log(f"Skipped: {url} - Reason: {reason}", "WARN")

	def log_url_error(self, url, error):
		"""
		Log when a URL crawl fails.

		Args:
			url (str): The URL that failed
			error (str): Error message
		"""
		self.log(f"Error crawling: {url} - {error}", "ERROR")

	def log_links_discovered(self, url, links_count):
		"""
		Log when new links are discovered from a page.

		Args:
			url (str): The URL that contained the links
			links_count (int): Number of new links discovered
		"""
		if links_count > 0:
			self.log(f"Discovered {links_count} new links from: {url}", "DEBUG")

	def log_warc_creation(self, warc_path, pages_count):
		"""
		Log WARC file creation.

		Args:
			warc_path (str): Path to the created WARC file
			pages_count (int): Number of pages in the WARC
		"""
		self.log(f"Total pages to archive: {pages_count}")
		self.log(f"Writing WARC file: {warc_path}")

	def log_crawl_complete(self, total_pages, crawl_time, warc_path):
		"""
		Log crawl completion.

		Args:
			total_pages (int): Total number of pages crawled
			crawl_time (int): Total crawl time in seconds
			warc_path (str): Final WARC file path
		"""
		self.log("=" * 50)
		self.log(f"Crawl completed successfully!")
		self.log(f"Total pages crawled: {total_pages}")
		self.log(f"Total crawl time: {crawl_time} seconds")
		self.log(f"WARC file: {warc_path}")
		self.log(f"Log file: {self.log_file_path}")

	def log_crawl_error(self, error):
		"""
		Log crawl error.

		Args:
			error (str): Error message
		"""
		self.log(f"Crawl failed: {error}", "ERROR")

def sanitize_metadata_field(text):
	"""
	Sanitize metadata fields to prevent security issues while allowing normal characters.

	Args:
		text (str): The text to sanitize

	Returns:
		str: Sanitized text safe for metadata fields
	"""
	if not text:
		return ""

	# Remove control characters and potentially dangerous sequences
	text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
	# Remove script tags and other HTML/XML that could be dangerous
	text = re.sub(r'<[^>]*>', '', text)
	# Remove potential command injection characters
	text = re.sub(r'[;&|`$]', '', text)
	# Limit length to prevent abuse
	text = text[:500]

	return text.strip()

def validate_url(url):
	"""
	Validate and sanitize URL input to prevent security issues.

	Args:
		url (str): The URL to validate

	Returns:
		tuple: (is_valid, sanitized_url, error_message)
	"""
	if not url:
		return False, None, "URL is required"

	# Basic length check
	if len(url) > 2048:
		return False, None, "URL is too long"

	# Check for valid URL format
	parsed = urlparse(url)
	if not parsed.scheme or not parsed.netloc:
		return False, None, "Invalid URL format"

	# Only allow http and https schemes
	if parsed.scheme not in ['http', 'https']:
		return False, None, "Only HTTP and HTTPS URLs are allowed"

	# Check for potentially dangerous characters (XSS prevention)
	if any(char in url for char in ['<', '>']):
		return False, None, "URL contains potentially dangerous characters"

	return True, url, None

def validate_archive_id(archive_id):
	"""
	Validate archive ID to ensure it's a positive integer.

	Args:
		archive_id: The archive ID to validate

	Returns:
		tuple: (is_valid, sanitized_id, error_message)
	"""
	try:
		archive_id = int(archive_id)
		if archive_id <= 0:
			return False, None, "Invalid archive ID"
		return True, archive_id, None
	except (ValueError, TypeError):
		return False, None, "Invalid archive ID format"

def validate_regex_pattern(pattern):
	"""
	Validate regex pattern to ensure it's safe and compiles correctly.

	Args:
		pattern (str): The regex pattern to validate

	Returns:
		tuple: (is_valid, error_message)
	"""
	if not pattern:
		return False, "Pattern cannot be empty"

	if len(pattern) > 1000:
		return False, "Pattern too long (max 1000 characters)"

	# Check for potentially dangerous patterns that could cause ReDoS
	dangerous_patterns = [
		r'\(\?\=.*\*',  # Positive lookahead with quantifier
		r'\(\?\=.*\+',  # Positive lookahead with quantifier
		r'\(\?\=.*\{',  # Positive lookahead with quantifier
		r'\(\?\=.*\?',  # Positive lookahead with quantifier
		r'\(\?\=.*\*.*\*',  # Nested quantifiers in lookahead
		r'\(\?\=.*\+.*\+',  # Nested quantifiers in lookahead
		r'\(\?\=.*\{.*\{',  # Nested quantifiers in lookahead
		r'\(\?\=.*\?.*\?',  # Nested quantifiers in lookahead
	]

	for dangerous in dangerous_patterns:
		if re.search(dangerous, pattern):
			return False, "Pattern contains potentially dangerous regex constructs"

	# Try to compile the pattern
	try:
		re.compile(pattern)
		return True, None
	except re.error as e:
		return False, f"Invalid regex pattern: {str(e)}"

def should_ignore_url(url):
	"""
	Check if a URL should be ignored based on ignore patterns.

	Args:
		url (str): The URL to check

	Returns:
		tuple: (should_ignore, matching_pattern, description)
	"""
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT pattern, description FROM ignore_patterns WHERE enabled = 1')
	patterns = cursor.fetchall()
	conn.close()

	for pattern, description in patterns:
		try:
			if re.search(pattern, url):
				return True, pattern, description
		except re.error:
			# Skip invalid patterns (shouldn't happen if validation works)
			continue

	return False, None, None

def load_default_ignore_patterns(cursor):
	"""
	Load default ignore patterns from default_ignores.tsv file.

	Args:
		cursor: Database cursor for executing queries
	"""
	default_file = cfg.get('general', 'default_ignores')

	if not os.path.exists(default_file):
		return

	try:
		with open(default_file, 'r', encoding='utf-8') as f:
			for line_num, line in enumerate(f, 1):
				line = line.strip()
				if not line or line.startswith('#'):  # Skip empty lines and comments
					continue

				# Split on tab character
				parts = line.split('\t', 1)
				if len(parts) != 2:
					print(f"[WARN] Invalid format in default_ignores.tsv line {line_num}: {line}", file=sys.stderr)
					continue

				pattern = parts[0].strip()
				description = parts[1].strip()

				if not pattern:
					print(f"[WARN] Empty pattern in default_ignores.tsv line {line_num}", file=sys.stderr)
					continue

				# Validate pattern
				is_valid, error_msg = validate_regex_pattern(pattern)
				if not is_valid:
					print(f"[WARN] Invalid pattern in default_ignores.tsv line {line_num}: {error_msg}", file=sys.stderr)
					continue

				# Check if pattern already exists
				cursor.execute('SELECT id FROM ignore_patterns WHERE pattern = ?', (pattern,))
				if not cursor.fetchone():
					# Insert new pattern
					cursor.execute('''
						INSERT INTO ignore_patterns (pattern, description) VALUES (?, ?)
					''', (pattern, description))
					print(f"[INFO] Added default ignore pattern: {description}", file=sys.stderr)

	except Exception as e:
		print(f"[ERROR] Error loading default ignore patterns: {str(e)}", file=sys.stderr)

def init_db():
	"""
	Initialize the SQLite database and create the necessary tables if they don't exist.

	Creates tables to store:
	- Archives: crawled archive information
	- Ignore patterns: regex patterns for URL exclusion during crawling
	"""
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()

	# Create archives table
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS archives (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL,
			mode TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now', 'localtime')),
			warc_file TEXT NOT NULL,
			log_file TEXT,
			pages_crawled INTEGER DEFAULT 0,
			status TEXT DEFAULT 'completed',
			crawl_time INTEGER DEFAULT 0,
			max_size INTEGER DEFAULT 0
		)
	''')

	# Create ignore_patterns table
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS ignore_patterns (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL UNIQUE,
			description TEXT,
			created_at TEXT DEFAULT (datetime('now', 'localtime')),
			enabled INTEGER DEFAULT 1
		)
	''')

	# Load default ignore patterns from TSV file
	load_default_ignore_patterns(cursor)

	conn.commit()
	conn.close()

# Global variables to store crawl progress
crawl_progress = {}
crawl_stats = {}
crawl_abort_flags = {}

def clear_crawl_state(url=None):
	"""
	Clear global crawl state variables for a specific URL or all URLs.

	Args:
		url (str, optional): Specific URL to clear state for. If None, clears all state.
	"""
	global crawl_progress, crawl_stats, crawl_abort_flags

	if url:
		# Clear state for specific URL
		crawl_abort_flags.pop(url, None)
		crawl_stats.pop(url, None)
		# Remove all progress entries that start with this URL
		urls_to_remove = [k for k in crawl_progress.keys() if k.startswith(url) or url in k]
		for k in urls_to_remove:
			crawl_progress.pop(k, None)
	else:
		# Clear all state
		crawl_progress.clear()
		crawl_stats.clear()
		crawl_abort_flags.clear()

def rewrite_html_urls(html_content, archive_id, base_url):
	"""
	Rewrite URLs in HTML content to point to archived files for proper viewing.

	Args:
		html_content (str): The HTML content to process
		archive_id (int): The archive ID for URL rewriting
		base_url (str): The base URL for relative URL resolution

	Returns:
		str: HTML content with rewritten URLs
	"""
	soup = BeautifulSoup(html_content, 'html.parser')

	# Get all URLs from the WARC archive
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT warc_file FROM archives WHERE id = ?', (archive_id,))
	archive_result = cursor.fetchone()
	conn.close()

	if not archive_result:
		return html_content

	warc_file = archive_result[0]
	url_to_index = {}

	# Build mapping of URLs to record indices
	try:
		with open(warc_file, 'rb') as stream:
			for i, record in enumerate(ArchiveIterator(stream)):
				if record.rec_type == 'response':
					record_url = record.rec_headers.get_header('WARC-Target-URI')
					if record_url:
						url_to_index[record_url] = i
	except:
		return html_content

	# Rewrite img src and srcset attributes
	for img in soup.find_all('img', src=True):
		original_src = img['src']
		absolute_url = urljoin(base_url, original_src)
		if absolute_url in url_to_index:
			img['src'] = f'/raw_file/{archive_id}/{url_to_index[absolute_url]}'
	for img in soup.find_all('img', srcset=True):
		new_srcset_entries = []
		candidates = [s.strip() for s in img['srcset'].split(',')]
		for candidate in candidates:
			parts = candidate.strip().split()
			if not parts:
				continue
			srcset_url = parts[0]
			descriptor = parts[1] if len(parts) > 1 else ''
			absolute_url = urljoin(base_url, srcset_url).split('#')[0]
			if absolute_url in url_to_index:
				new_url = f'/raw_file/{archive_id}/{url_to_index[absolute_url]}'
				new_srcset_entries.append(f'{new_url} {descriptor}'.strip())
			else:
				# fallback to original
				new_srcset_entries.append(candidate)
		img['srcset'] = ', '.join(new_srcset_entries)

	# Rewrite CSS background-image URLs in style attributes
	for element in soup.find_all(style=True):
		style = element['style']
		# Find url() declarations in inline styles
		url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
		def replace_url(match):
			url = match.group(1).strip()
			if url and not url.startswith('data:'):
				absolute_url = urljoin(base_url, url)
				if absolute_url in url_to_index:
					return f'url(/raw_file/{archive_id}/{url_to_index[absolute_url]})'
			return match.group(0)
		element['style'] = re.sub(url_pattern, replace_url, style)

	# Rewrite link href attributes for CSS files
	for link in soup.find_all('link', href=True):
		original_href = link['href']
		absolute_url = urljoin(base_url, original_href)
		if absolute_url in url_to_index:
			link['href'] = f'/raw_file/{archive_id}/{url_to_index[absolute_url]}'

	# Rewrite a href attributes
	for a in soup.find_all('a', href=True):
		original_href = a['href']
		absolute_url = urljoin(base_url, original_href)
		if absolute_url in url_to_index:
			a['href'] = f'/view_file/{archive_id}/{url_to_index[absolute_url]}'

	# Rewrite script src attributes
	for script in soup.find_all('script', src=True):
		original_src = script['src']
		absolute_url = urljoin(base_url, original_src)
		if absolute_url in url_to_index:
			script['src'] = f'/raw_file/{archive_id}/{url_to_index[absolute_url]}'

	# Rewrite frame and iframe src attributes (viewer-friendly URLs)
	for frame in soup.find_all(['frame', 'iframe'], src=True):
		original_src = frame['src']
		absolute_url = urljoin(base_url, original_src)
		if absolute_url in url_to_index:
			frame['src'] = f'/raw_file/{archive_id}/{url_to_index[absolute_url]}'

	# Convert <frameset> structures into <div> + <iframe> layout
	frameset = soup.find('frameset')
	if frameset:
		# Extract frame definitions
		colspec = frameset.get('cols')
		rowspec = frameset.get('rows')
		frames = frameset.find_all('frame', src=True)

		# Create replacement container
		new_container = soup.new_tag('div')
		new_container['class'] = 'frameset'
		new_container['style'] = 'width:100%; height:100%; display:flex; flex-direction:{};'.format(
			'column' if rowspec else 'row'
		)

		# Parse column widths if any
		size_specs = []
		if colspec:
			size_specs = [c.strip() for c in colspec.split(',')]
		elif rowspec:
			size_specs = [r.strip() for r in rowspec.split(',')]

		for i, frame in enumerate(frames):
			src = frame['src']
			name = frame.get('name', '')
			iframe = soup.new_tag('iframe', src=src)
			if name:
				iframe['name'] = name
			iframe['style'] = 'border:none; height:100%;'

			# Apply width/height according to frameset specs
			if size_specs:
				size = size_specs[i] if i < len(size_specs) else '*'
				if size.endswith('*'):
					# Flexible
					iframe['style'] += ' flex:1;'
				elif size.endswith('%'):
					if rowspec:
						iframe['style'] += f' height:{size};'
					else:
						iframe['style'] += f' width:{size};'
				else:
					# Fixed pixel size
					if rowspec:
						iframe['style'] += f' height:{size}px;'
					else:
						iframe['style'] += f' width:{size}px;'
			else:
				iframe['style'] += ' flex:1;'

			new_container.append(iframe)

		# Replace frameset with new container
		frameset.replace_with(new_container)

	return str(soup)

def rewrite_css_urls(css_content, archive_id, base_url):
	"""
	Rewrite URLs in CSS content to point to archived files for proper viewing.

	Args:
		css_content (str): The CSS content to process
		archive_id (int): The archive ID for URL rewriting
		base_url (str): The base URL for relative URL resolution

	Returns:
		str: CSS content with rewritten URLs
	"""

	# Get all URLs from the WARC archive
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT warc_file FROM archives WHERE id = ?', (archive_id,))
	archive_result = cursor.fetchone()
	conn.close()

	if not archive_result:
		return css_content

	warc_file = archive_result[0]
	url_to_index = {}

	# Build mapping of URLs to record indices
	try:
		with open(warc_file, 'rb') as stream:
			for i, record in enumerate(ArchiveIterator(stream)):
				if record.rec_type == 'response':
					record_url = record.rec_headers.get_header('WARC-Target-URI')
					if record_url:
						url_to_index[record_url] = i
	except:
		return css_content

	# Rewrite url() declarations in CSS
	url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
	def replace_url(match):
		url = match.group(1).strip()
		if url and not url.startswith('data:'):
			absolute_url = urljoin(base_url, url)
			if absolute_url in url_to_index:
				return f'url(/raw_file/{archive_id}/{url_to_index[absolute_url]})'
		return match.group(0)

	return re.sub(url_pattern, replace_url, css_content)

class WebCrawler:
	"""
	A web crawler class that crawls websites and creates WARC archives.

	This class handles the crawling of web pages, extraction of resources,
	and creation of WARC (Web ARChive) files for archival purposes.
	"""

	def __init__(self, start_url, mode='simple', max_size=0, niceness=True, restrictpage=True):
		"""
		Initialize the WebCrawler with configuration parameters.

		Args:
			start_url (str): The URL to start crawling from
			mode (str): Crawling mode ('simple' or 'advanced')
			max_size (int): Maximum file size to download (0 = no limit)
			niceness (bool): Whether to add delays between requests
			restrictpage (bool): Whether to restrict crawling to same folder
		"""
		self.start_url = start_url
		self.mode = mode
		self.max_size = max_size
		self.niceness = niceness
		self.restrictpage = restrictpage
		self.visited_urls = set()
		self.to_visit = [start_url]
		self.crawled_pages = []
		self.base_host = urlparse(start_url).netloc
		if self.restrictpage:
			self.base_path = urlparse(start_url).path
		else:
			self.base_path = '/'.join(urlparse(start_url).path.split('/')[:-1]) + '/'
		self.temp_dir = None
		self.warc_file = None
		self.logger = None  # Will be initialized in crawl() method
		self.driver = None  # Selenium WebDriver for Advanced mode

	def is_same_host(self, url):
		"""
		Check if URL is from the same host as the starting URL.

		Args:
			url (str): The URL to check

		Returns:
			bool: True if URL is from same host, False otherwise
		"""
		parsed = urlparse(url)
		return parsed.netloc == self.base_host

	def is_same_host_and_folder(self, url):
		"""
		Check if URL is from same host and within the same folder structure.

		Args:
			url (str): The URL to check

		Returns:
			bool: True if URL is from same host and folder, False otherwise
		"""
		parsed = urlparse(url)
		if parsed.netloc != self.base_host:
			return False

		# Check if it's not a parent folder
		url_path = parsed.path
		if not url_path.startswith(self.base_path):
			return False
		return True

	def infer_content_type_from_url(self, url, current_content_type=None):
		"""
		Infer content type from URL file extension if current content type is missing or incorrect.

		Args:
			url (str): The URL to analyze
			current_content_type (str): Current content type (if any)

		Returns:
			str: Inferred or corrected content type
		"""
		# If we have a proper content type, use it
		if current_content_type and current_content_type.strip():
			return current_content_type

		# Otherwise, try to infer from URL extension
		parsed_url = urlparse(url)
		path = parsed_url.path.lower()

		if path.endswith('.png'):
			return 'image/png'
		elif path.endswith('.jpg') or path.endswith('.jpeg'):
			return 'image/jpeg'
		elif path.endswith('.gif'):
			return 'image/gif'
		elif path.endswith('.webp'):
			return 'image/webp'
		elif path.endswith('.svg'):
			return 'image/svg+xml'
		elif path.endswith('.ico'):
			return 'image/x-icon'
		elif path.endswith('.bmp'):
			return 'image/bmp'
		elif path.endswith('.tiff') or path.endswith('.tif'):
			return 'image/tiff'
		elif path.endswith('.css'):
			return 'text/css'
		elif path.endswith('.js'):
			return 'application/javascript'
		elif path.endswith('.json'):
			return 'application/json'
		elif path.endswith('.xml'):
			return 'application/xml'
		elif path.endswith('.pdf'):
			return 'application/pdf'
		elif path.endswith('.zip'):
			return 'application/zip'
		elif path.endswith('.mp4'):
			return 'video/mp4'
		elif path.endswith('.webm'):
			return 'video/webm'
		elif path.endswith('.ogg'):
			return 'video/ogg'
		elif path.endswith('.mp3'):
			return 'audio/mpeg'
		elif path.endswith('.wav'):
			return 'audio/wav'
		elif path.endswith('.woff'):
			return 'font/woff'
		elif path.endswith('.woff2'):
			return 'font/woff2'
		elif path.endswith('.ttf'):
			return 'font/ttf'
		elif path.endswith('.eot'):
			return 'application/vnd.ms-fontobject'
		elif path.endswith('.otf'):
			return 'font/otf'
		else:
			return 'application/octet-stream'

	def get_file_extension_from_content_type(self, content_type, url_path=None):
		"""
		Get appropriate file extension from content type and optionally URL path.

		Args:
			content_type (str): The MIME content type
			url_path (str): Optional URL path to extract extension from

		Returns:
			str: Appropriate file extension (e.g., '.css', '.js', '.png')
		"""
		if not content_type:
			return '.bin'

		content_type_lower = content_type.lower()

		# CSS files
		if 'css' in content_type_lower:
			return '.css'

		# JavaScript files
		elif 'javascript' in content_type_lower or 'ecmascript' in content_type_lower:
			return '.js'

		# Images - try to get specific extension from content type
		elif 'image/' in content_type_lower:
			if 'png' in content_type_lower:
				return '.png'
			elif 'jpeg' in content_type_lower or 'jpg' in content_type_lower:
				return '.jpg'
			elif 'gif' in content_type_lower:
				return '.gif'
			elif 'webp' in content_type_lower:
				return '.webp'
			elif 'svg' in content_type_lower:
				return '.svg'
			elif 'ico' in content_type_lower:
				return '.ico'
			elif 'bmp' in content_type_lower:
				return '.bmp'
			elif 'tiff' in content_type_lower:
				return '.tiff'
			else:
				# Try to get extension from URL path, fallback to .bin
				if url_path:
					ext = os.path.splitext(url_path)[1]
					if ext:
						return ext
				return '.bin'

		# Fonts - try to get specific extension from content type
		elif 'font/' in content_type_lower:
			if 'woff2' in content_type_lower:
				return '.woff2'
			elif 'woff' in content_type_lower:
				return '.woff'
			elif 'ttf' in content_type_lower:
				return '.ttf'
			elif 'otf' in content_type_lower:
				return '.otf'
			elif 'eot' in content_type_lower:
				return '.eot'
			else:
				# Try to get extension from URL path, fallback to .font
				if url_path:
					ext = os.path.splitext(url_path)[1]
					if ext:
						return ext
				return '.font'

		# Video files
		elif 'video/' in content_type_lower:
			if 'mp4' in content_type_lower:
				return '.mp4'
			elif 'webm' in content_type_lower:
				return '.webm'
			elif 'ogg' in content_type_lower:
				return '.ogg'
			else:
				return '.bin'

		# Audio files
		elif 'audio/' in content_type_lower:
			if 'mpeg' in content_type_lower or 'mp3' in content_type_lower:
				return '.mp3'
			elif 'wav' in content_type_lower:
				return '.wav'
			elif 'ogg' in content_type_lower:
				return '.ogg'
			else:
				return '.bin'

		# Documents
		elif 'application/pdf' in content_type_lower:
			return '.pdf'
		elif 'application/zip' in content_type_lower:
			return '.zip'
		elif 'application/json' in content_type_lower:
			return '.json'
		elif 'application/xml' in content_type_lower or 'text/xml' in content_type_lower:
			return '.xml'

		# Text files
		elif 'text/html' in content_type_lower:
			return '.html'
		elif 'text/plain' in content_type_lower:
			return '.txt'
		elif 'text/csv' in content_type_lower:
			return '.csv'

		# Try to get extension from URL path if available
		if url_path:
			ext = os.path.splitext(url_path)[1]
			if ext:
				return ext

		# Default fallback
		return '.bin'

	def extract_media_links(self, html_content, base_url):
		"""
		Extract media (images, audio, video) URLs from HTML content.

		Args:
			html_content (str): HTML content to parse
			base_url (str): Base URL for resolving relative links

		Returns:
			list: List of absolute URLs for media files
		"""
		soup = BeautifulSoup(html_content, 'html.parser')
		links = []

		# Images
		for img in soup.find_all('img', src=True):
			links.append(urljoin(base_url, img['src']))
		for img in soup.find_all('img', srcset=True):
			for candidate in img['srcset'].split(','):
				parts = candidate.strip().split()
				if parts:
					links.append(urljoin(base_url, parts[0]))

		# Videos
		for video in soup.find_all('video', src=True):
			links.append(urljoin(base_url, video['src']))
		for source in soup.find_all('source', src=True):
			links.append(urljoin(base_url, source['src']))

		# Audio
		for audio in soup.find_all('audio', src=True):
			links.append(urljoin(base_url, audio['src']))

		# Picture sources
		for source in soup.find_all('source', srcset=True):
			for candidate in source['srcset'].split(','):
				parts = candidate.strip().split()
				if parts:
					links.append(urljoin(base_url, parts[0]))

		# Deduplicate and filter to same host
		links = [l.split('#')[0] for l in links if self.is_same_host(l)]
		return list(set(links))

	def extract_links(self, html_content, base_url):
		"""
		Extract all resource links from HTML content for further crawling,
		excluding media which is handled by extract_media_links().

		Args:
			html_content (str): The HTML content to parse
			base_url (str): The base URL for resolving relative links

		Returns:
			list: List of unique URLs found in the HTML content
		"""
		soup = BeautifulSoup(html_content, 'html.parser')
		links = []

		# Page links (same host, same folder)
		for link in soup.find_all('a', href=True):
			href = link['href']
			absolute_url = urljoin(base_url, href).split('#')[0]
			if self.is_same_host_and_folder(absolute_url):
				links.append(absolute_url)

		# CSS files (any host)
		for link in soup.find_all('link', rel='stylesheet', href=True):
			href = link['href']
			absolute_url = urljoin(base_url, href).split('#')[0]
			links.append(absolute_url)

		# JavaScript files (any host)
		for script in soup.find_all('script', src=True):
			src = script['src']
			absolute_url = urljoin(base_url, src).split('#')[0]
			links.append(absolute_url)

		# Fonts from CSS @font-face rules
		font_urls = re.findall(r'url\(["\']?([^"\'()]+)["\']?\)', html_content)
		for font_url in font_urls:
			font_url = font_url.strip()
			if font_url and not font_url.startswith('data:'):
				absolute_url = urljoin(base_url, font_url).split('#')[0]
				links.append(absolute_url)

		# Frames and iframes (same host, same folder)
		for frame in soup.find_all(['frame', 'iframe'], src=True):
			src = frame['src']
			absolute_url = urljoin(base_url, src).split('#')[0]
			if self.is_same_host_and_folder(absolute_url):
				links.append(absolute_url)

		# Icons / favicons (same host)
		for link in soup.find_all('link', href=True):
			rel = link.get('rel', [])
			if 'icon' in rel or 'shortcut' in rel:
				href = link['href']
				absolute_url = urljoin(base_url, href).split('#')[0]
				if self.is_same_host(absolute_url):
					links.append(absolute_url)

		# Media links (images, audio, video)
		media_links = self.extract_media_links(html_content, base_url)
		links.extend(media_links)

		return list(set(links))  # Deduplicate

	def extract_css_links(self, css_content, base_url):
		"""
		Extract URLs from CSS content for further crawling.

		Args:
			css_content (str): The CSS content to parse
			base_url (str): The base URL for resolving relative links

		Returns:
			list: List of unique URLs found in the CSS content
		"""
		links = []

		# Extract URLs from url() declarations - improved regex to be non-greedy
		url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
		urls = re.findall(url_pattern, css_content)

		for url in urls:
			url = url.strip()
			if url and not url.startswith('data:'):  # Skip data URLs
				absolute_url = urljoin(base_url, url).split('#')[0]
				if self.is_same_host(absolute_url):
					links.append(absolute_url)

		# Extract @import URLs
		import_pattern = r'@import\s+["\']([^"\']+)["\']'
		imports = re.findall(import_pattern, css_content)

		for import_url in imports:
			absolute_url = urljoin(base_url, import_url).split('#')[0]
			if self.is_same_host(absolute_url):
				links.append(absolute_url)

		return list(set(links))  # Remove duplicates

	def _wait_for_dynamic_content(self, driver):
		"""
		Wait for dynamic content to load by checking various indicators.

		Args:
			driver: Selenium WebDriver instance

		Returns:
			bool: True if dynamic content appears to be loaded
		"""
		try:
			# Check if jQuery is loaded and no active AJAX requests
			jquery_ready = driver.execute_script("""
				if (typeof jQuery !== 'undefined') {
					return jQuery.active === 0;
				}
				return true;
			""")

			# Check if common loading indicators are gone
			loading_indicators = [
				'[class*="loading"]',
				'[id*="loading"]',
				'[class*="spinner"]',
				'[id*="spinner"]',
				'.loading',
				'#loading'
			]

			loading_elements = 0
			for selector in loading_indicators:
				try:
					elements = driver.find_elements(By.CSS_SELECTOR, selector)
					loading_elements += len(elements)
				except:
					pass

			# Check if select elements have options (common for dynamic dropdowns)
			selects_with_options = driver.execute_script("""
				var selects = document.querySelectorAll('select');
				var populatedSelects = 0;
				for (var i = 0; i < selects.length; i++) {
					if (selects[i].options.length > 1) {
						populatedSelects++;
					}
				}
				return populatedSelects;
			""")

			# Check for Selectize.js elements (common dropdown library)
			selectize_ready = driver.execute_script("""
				var selectizeElements = document.querySelectorAll('.selectize-dropdown, .selectize-input');
				var populatedSelectize = 0;
				for (var i = 0; i < selectizeElements.length; i++) {
					var element = selectizeElements[i];
					// Check if Selectize dropdown has options
					var options = element.querySelectorAll('.option, .selectize-dropdown-content .option');
					if (options.length > 1) { // More than just placeholder
						populatedSelectize++;
					}
				}
				return populatedSelectize;
			""")

			# Check for other common dynamic dropdown libraries
			other_dropdowns = driver.execute_script("""
				var dropdowns = document.querySelectorAll('.dropdown-menu, .chosen-drop, .select2-results');
				var populatedDropdowns = 0;
				for (var i = 0; i < dropdowns.length; i++) {
					var dropdown = dropdowns[i];
					var options = dropdown.querySelectorAll('li, .option, a');
					if (options.length > 1) {
						populatedDropdowns++;
					}
				}
				return populatedDropdowns;
			""")

			# Only log if we found something interesting or there are issues
			if self.logger and (loading_elements > 0 or selects_with_options > 0 or selectize_ready > 0 or other_dropdowns > 0):
				self.logger.log(f"Dynamic content found - Loading: {loading_elements}, Selects: {selects_with_options}, Selectize: {selectize_ready}, Other dropdowns: {other_dropdowns}", "DEBUG")

			# Consider content loaded if:
			# 1. jQuery is ready (no active requests) AND
			# 2. No loading indicators visible AND
			# 3. Either no dynamic elements found OR at least one is populated
			has_dynamic_elements = (driver.execute_script("return document.querySelectorAll('select').length") > 0 or
								   driver.execute_script("return document.querySelectorAll('.selectize-dropdown, .dropdown-menu, .chosen-drop, .select2-results').length") > 0)

			return (jquery_ready and loading_elements == 0 and
					(not has_dynamic_elements or selects_with_options > 0 or selectize_ready > 0 or other_dropdowns > 0))

		except Exception as e:
			if self.logger:
				self.logger.log(f"Error in dynamic content check: {str(e)}", "DEBUG")
			# If there's an error, assume content is ready
			return True

	def _extract_js_links(self, driver, base_url):
		"""
		Extract links from JavaScript-generated content like select options and dropdown libraries.

		Args:
			driver: Selenium WebDriver instance
			base_url: Base URL for resolving relative links

		Returns:
			list: List of URLs found in JavaScript-generated content
		"""
		links = []
		try:
			# Extract links from select option values that look like URLs
			select_links = driver.execute_script("""
				var links = [];
				var selects = document.querySelectorAll('select');
				for (var i = 0; i < selects.length; i++) {
					var select = selects[i];
					for (var j = 0; j < select.options.length; j++) {
						var option = select.options[j];
						var value = option.value;
						// Check if the value looks like a URL or path
						if (value && (value.startsWith('http') || value.startsWith('/') || value.startsWith('./'))) {
							links.push(value);
						}
					}
				}
				return links;
			""")

			# Extract links from Selectize.js dropdown options
			selectize_links = driver.execute_script("""
				var links = [];
				var selectizeOptions = document.querySelectorAll('.selectize-dropdown .option, .selectize-dropdown-content .option');
				for (var i = 0; i < selectizeOptions.length; i++) {
					var option = selectizeOptions[i];
					var value = option.getAttribute('data-value') || option.textContent;
					if (value && (value.startsWith('http') || value.startsWith('/') || value.startsWith('./'))) {
						links.push(value);
					}
				}
				return links;
			""")

			# Extract links from other common dropdown libraries
			other_dropdown_links = driver.execute_script("""
				var links = [];
				// Chosen.js
				var chosenOptions = document.querySelectorAll('.chosen-drop .active-result');
				for (var i = 0; i < chosenOptions.length; i++) {
					var option = chosenOptions[i];
					var value = option.getAttribute('data-option-array-index') || option.textContent;
					if (value && (value.startsWith('http') || value.startsWith('/') || value.startsWith('./'))) {
						links.push(value);
					}
				}
				// Select2
				var select2Options = document.querySelectorAll('.select2-results .select2-result-label');
				for (var i = 0; i < select2Options.length; i++) {
					var option = select2Options[i];
					var value = option.getAttribute('data-select2-id') || option.textContent;
					if (value && (value.startsWith('http') || value.startsWith('/') || value.startsWith('./'))) {
						links.push(value);
					}
				}
				// Generic dropdown menus
				var dropdownOptions = document.querySelectorAll('.dropdown-menu a, .dropdown-menu li');
				for (var i = 0; i < dropdownOptions.length; i++) {
					var option = dropdownOptions[i];
					var value = option.getAttribute('href') || option.getAttribute('data-value') || option.textContent;
					if (value && (value.startsWith('http') || value.startsWith('/') || value.startsWith('./'))) {
						links.push(value);
					}
				}
				return links;
			""")

			# Extract links from any data attributes that might contain URLs
			data_links = driver.execute_script("""
				var links = [];
				var elements = document.querySelectorAll('[data-url], [data-href], [data-link]');
				for (var i = 0; i < elements.length; i++) {
					var element = elements[i];
					var url = element.getAttribute('data-url') || 
							 element.getAttribute('data-href') || 
							 element.getAttribute('data-link');
					if (url) {
						links.push(url);
					}
				}
				return links;
			""")

			# Combine all link sources
			all_js_links = select_links + selectize_links + other_dropdown_links + data_links

			# Convert relative URLs to absolute URLs
			for link in all_js_links:
				if link and not link.startswith('data:'):
					absolute_url = urljoin(base_url, link).split('#')[0]
					if self.is_same_host(absolute_url):
						links.append(absolute_url)

			# Only log if we found something interesting
			if self.logger and links:
				self.logger.log(f"Found {len(links)} links from JavaScript content (select: {len(select_links)}, selectize: {len(selectize_links)}, other: {len(other_dropdown_links)}, data: {len(data_links)})", "DEBUG")

			return list(set(links))  # Remove duplicates

		except Exception as e:
			if self.logger:
				self.logger.log(f"Error extracting JS links: {str(e)}", "DEBUG")
			return []

	def crawl_page_selenium(self, url):
		"""
		Crawl a single page using Selenium WebDriver for JavaScript-powered sites.
		For non-HTML resources (fonts, images, etc.), falls back to regular HTTP download.

		Args:
			url (str): The URL to crawl

		Returns:
			int or None: HTTP status code if successful, None if error
		"""
		# Check if crawl should be aborted
		if crawl_abort_flags.get(self.start_url, False):
			return None

		# Check if URL should be ignored
		should_ignore, matching_pattern, description = should_ignore_url(url)
		if should_ignore:
			# Update progress to show skipped URL
			crawl_progress[url] = {
				'status': 'skipped',
				'message': f'Skipped (matches pattern: {description or matching_pattern})',
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}
			# Log the skip
			if self.logger:
				self.logger.log_url_skip(url, f'matches pattern: {description or matching_pattern}')
			self.visited_urls.add(url)
			return 200  # Return 200 to indicate "processed" (even though skipped)

		# Check content type to determine if this is a non-HTML resource
		content_type = 'text/html'  # Default assumption
		is_non_html = False

		# Skip HEAD request for data URLs since they are inline data, not HTTP resources
		if url.startswith('data:'):
			# Extract content type from data URL if present
			if ';' in url:
				content_type = url.split(';')[0].split(':')[1] if ':' in url else ''
			else:
				content_type = ''

			# Check if it's a non-HTML resource
			if content_type and not content_type.startswith('text/html'):
				is_non_html = True
				if self.logger:
					self.logger.log(f"Detected non-HTML data URL (Content-Type: {content_type}): {url[:100]}...", "DEBUG")
		else:
			try:
				# Make a HEAD request to get the actual content type
				headers = {'User-Agent': cfg.get('simple', 'user_agent')}
				response = make_http_request_with_retry('head', url, logger=self.logger, timeout=int(cfg.get('connections', 'timeout')), allow_redirects=True, headers=headers)
				content_type = response.headers.get('content-type', '').lower()

				# Infer content type from URL if needed
				content_type = self.infer_content_type_from_url(url, content_type)

				# Check if it's a non-HTML resource
				if content_type and not content_type.startswith('text/html'):
					is_non_html = True
					if self.logger:
						self.logger.log(f"Detected non-HTML resource (Content-Type: {content_type}): {url}", "DEBUG")

			except Exception as e:
				# If HEAD request fails, assume it's HTML and proceed with Selenium
				if self.logger:
					self.logger.log(f"HEAD request failed for {url}, assuming HTML: {str(e)}", "DEBUG")

		try:
			if is_non_html:
				# Handle data URLs specially since they don't require HTTP requests
				if url.startswith('data:'):
					if self.logger:
						self.logger.log(f"Processing data URL directly: {url[:100]}...", "DEBUG")

					# Parse data URL to extract content
					import base64
					if ',' in url:
						header, data = url.split(',', 1)
						# Extract content type from header
						if ';' in header:
							actual_content_type = header.split(';')[0].split(':')[1] if ':' in header else ''
						else:
							actual_content_type = ''

						# Decode base64 data if needed
						if 'base64' in header:
							try:
								content_bytes = base64.b64decode(data)
							except Exception as e:
								if self.logger:
									self.logger.log(f"Failed to decode base64 data URL: {str(e)}", "WARN")
								return None
						else:
							# URL-encoded data
							import urllib.parse
							content_bytes = urllib.parse.unquote(data).encode('utf-8')

						final_url = url
						status_code = 200

						# Log the crawl attempt
						if self.logger:
							self.logger.log_url_crawl(url, status_code, actual_content_type, len(content_bytes))

						# Update progress
						crawl_progress[url] = {
							'status': 'crawled',
							'status_code': status_code,
							'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
						}

						# Determine file extension and create filename
						ext = self.get_file_extension_from_content_type(actual_content_type)

						filename = f"{len(self.crawled_pages):04d}_data_url{ext}"
						filepath = os.path.join(self.temp_dir, filename)

						# Write content to file
						with open(filepath, 'wb') as f:
							f.write(content_bytes)

						# Log the crawl with actual size
						if self.logger:
							self.logger.log_url_crawl(url, status_code, actual_content_type, len(content_bytes))

						# For text content, also collect it for link extraction
						text_content = ""
						if 'text/' in actual_content_type or 'application/javascript' in actual_content_type or 'application/css' in actual_content_type:
							text_content = content_bytes.decode('utf-8', errors='ignore')

						# Extract links from text content
						links = []
						if text_content:
							links = self.extract_links(text_content, final_url)
							if 'css' in actual_content_type:
								css_links = self.extract_css_links(text_content, final_url)
								links.extend(css_links)

						# Store page info for later WARC creation
						self.crawled_pages.append({
							'url': url,
							'filepath': filepath,
							'status_code': status_code,
							'content_type': actual_content_type
						})
						self.visited_urls.add(url)

						# Add discovered links to the queue
						for link in links:
							if link not in self.visited_urls and link not in self.to_visit:
								self.to_visit.append(link)

						return status_code
					else:
						if self.logger:
							self.logger.log(f"Invalid data URL format: {url[:100]}...", "WARN")
						return None
				else:
					# For non-HTML resources, download directly using requests
					headers = {'User-Agent': cfg.get('simple', 'user_agent')}
					response = make_http_request_with_retry('get', url, logger=self.logger, timeout=int(cfg.get('connections', 'timeout')), allow_redirects=True, headers=headers, stream=True)
					final_url = response.url
					status_code = response.status_code
					actual_content_type = response.headers.get('content-type', content_type)

					# Get content length for size checking
					content_length = response.headers.get('Content-Length')

					# Update progress
					crawl_progress[url] = {
						'status': 'crawled',
						'status_code': status_code,
						'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					}

					# Determine file extension and create filename
					parsed_url = urlparse(url)
					path = parsed_url.path
					ext = self.get_file_extension_from_content_type(actual_content_type, path)

					filename = f"{len(self.crawled_pages):04d}_{path.replace('/', '_')}{ext}"
					filepath = os.path.join(self.temp_dir, filename)

					# Stream content to file and collect text for link extraction
					text_content = ""
					actual_size = 0
					if 'text/' in actual_content_type or 'application/javascript' in actual_content_type or 'application/css' in actual_content_type:
						# Stream text content and collect it for link extraction
						with open(filepath, 'w', encoding='utf-8') as f:
							for chunk in response.iter_content(chunk_size=8192):
								if chunk:  # Filter out keep-alive chunks
									# Decode bytes to string if needed
									if isinstance(chunk, bytes):
										chunk = chunk.decode('utf-8', errors='ignore')
									f.write(chunk)
									text_content += chunk
									actual_size += len(chunk.encode('utf-8'))  # Count bytes, not characters
					else:
						# Stream binary content directly to file
						with open(filepath, 'wb') as f:
							for chunk in response.iter_content(chunk_size=8192):
								if chunk:  # Filter out keep-alive chunks
									f.write(chunk)
									actual_size += len(chunk)

					# Update the crawl log with actual size
					if self.logger and actual_size > 0:
						self.logger.log_url_crawl(url, status_code, actual_content_type, actual_size)

					# Extract links from text content
					links = []
					if text_content:
						links = self.extract_links(text_content, final_url)
						if 'css' in actual_content_type:
							css_links = self.extract_css_links(text_content, final_url)
							links.extend(css_links)

					# Store page info for later WARC creation
					self.crawled_pages.append({
						'url': url,
						'filepath': filepath,
						'status_code': status_code,
						'content_type': actual_content_type
					})
					self.visited_urls.add(url)

					# Add discovered links to the queue
					for link in links:
						if link not in self.visited_urls and link not in self.to_visit:
							self.to_visit.append(link)

					return status_code

			else:
				# For HTML pages, use Selenium for JavaScript rendering
				self.driver.get(url)

				# Wait for page to load and get final URL (after redirects)
				WebDriverWait(self.driver, 10).until(
					lambda driver: driver.execute_script("return document.readyState") == "complete"
				)

				final_url = self.driver.current_url

				# Wait for JavaScript to finish loading dynamic content
				try:
					# Wait for common indicators that dynamic content has loaded
					WebDriverWait(self.driver, 15).until(
						lambda driver: self._wait_for_dynamic_content(driver)
					)
				except TimeoutException:
					if self.logger:
						self.logger.log("Timeout waiting for dynamic content, proceeding anyway", "WARN")

				page_source = self.driver.page_source
				page_content = page_source
				status_code = 200  # Selenium doesn't provide HTTP status codes directly
				actual_content_type = self.infer_content_type_from_url(url, content_type)

				# Log the crawl attempt
				if self.logger:
					self.logger.log_url_crawl(url, status_code, actual_content_type, str(len(page_source)))

				# Update progress
				crawl_progress[url] = {
					'status': 'crawled',
					'status_code': status_code,
					'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				}

				# Determine file extension and create filename
				parsed_url = urlparse(url)
				path = parsed_url.path
				ext = self.get_file_extension_from_content_type(actual_content_type, path)

				filename = f"{len(self.crawled_pages):04d}_{path.replace('/', '_')}{ext}"
				filepath = os.path.join(self.temp_dir, filename)

				# Save content
				with open(filepath, 'w', encoding='utf-8') as f:
					f.write(page_source)

				# Extract links from HTML page source
				links = self.extract_links(page_content, final_url)

			# For HTML pages, log select info if we found interesting elements
			if not is_non_html and self.logger:
				select_info = self.driver.execute_script("""
					var selects = document.querySelectorAll('select');
					var selectData = [];
					for (var i = 0; i < selects.length; i++) {
						var select = selects[i];
						selectData.push({
							id: select.id || 'no-id',
							name: select.name || 'no-name',
							className: select.className || 'no-class',
							optionCount: select.options.length,
							options: Array.from(select.options).map(opt => opt.value + ':' + opt.text)
						});
					}
					return selectData;
				""")
				# Only log if we found select elements with multiple options or interesting classes
				interesting_selects = [s for s in select_info if s['optionCount'] > 1 or 'selectize' in s['className'].lower()]
				if interesting_selects:
					self.logger.log(f"Found {len(interesting_selects)} populated select elements: {interesting_selects}", "DEBUG")

			# For HTML pages, also extract links from JavaScript-generated content
			js_links = []
			if not is_non_html:
				# Also extract links from JavaScript-generated content (select options, etc.)
				js_links = self._extract_js_links(self.driver, final_url)
				if js_links:
					links.extend(js_links)

			# Only log link extraction summary if we found JavaScript links or many total links
			if self.logger and (js_links or len(links) > 10):
				self.logger.log(f"Extracted {len(links)} total links ({len(js_links)} from JavaScript content)", "DEBUG")

			new_links_count = 0
			for link in links:
				# Check if link should be ignored before adding to queue
				should_ignore, matching_pattern, description = should_ignore_url(link)
				if should_ignore:
					# Mark as skipped in progress
					crawl_progress[link] = {
						'status': 'skipped',
						'message': f'Skipped (matches pattern: {description or matching_pattern})',
						'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					}
					self.visited_urls.add(link)
				elif link not in self.visited_urls and link not in self.to_visit:
					self.to_visit.append(link)
					new_links_count += 1

			# Update stats with newly discovered URLs
			if new_links_count > 0:
				crawl_stats[self.start_url]['total_discovered'] = len(self.visited_urls) + len(self.to_visit)
				# Log links discovery
				if self.logger:
					self.logger.log_links_discovered(url, new_links_count)

			self.crawled_pages.append({
				'url': url,
				'filepath': filepath,
				'status_code': status_code,
				'content_type': actual_content_type
			})

			self.visited_urls.add(url)
			return status_code

		except Exception as e:
			crawl_progress[url] = {
				'status': 'error',
				'error': str(e),
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}
			# Log the error
			if self.logger:
				self.logger.log_url_error(url, str(e))
			return None

	def crawl_page(self, url):
		"""
		Crawl a single page and extract its content and links.

		Args:
			url (str): The URL to crawl

		Returns:
			int or None: HTTP status code if successful, None if error
		"""
		# Check if crawl should be aborted
		if crawl_abort_flags.get(self.start_url, False):
			return None

		# Check if URL should be ignored
		should_ignore, matching_pattern, description = should_ignore_url(url)
		if should_ignore:
			# Update progress to show skipped URL
			crawl_progress[url] = {
				'status': 'skipped',
				'message': f'Skipped (matches pattern: {description or matching_pattern})',
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}
			# Log the skip
			if self.logger:
				self.logger.log_url_skip(url, f'matches pattern: {description or matching_pattern}')
			self.visited_urls.add(url)
			return 200  # Return 200 to indicate "processed" (even though skipped)

		try:
			headers = {
				"User-Agent": cfg.get('simple', 'user_agent'),
				"Accept": cfg.get('simple', 'accept_header'),
				"Accept-Language": cfg.get('simple', 'accept_language')
			}

			response = make_http_request_with_retry('head', url, logger=self.logger, allow_redirects=True, headers=headers)
			content_length = response.headers.get('Content-Length')
			content_type = response.headers.get('content-type', '')
			status_code = response.status_code

			# Infer content type from URL if needed
			content_type = self.infer_content_type_from_url(url, content_type)

			# Check size of file
			if self.max_size > 0:
				if content_length is not None and int(content_length) > self.max_size:
					status_code = 413

			# Update progress
			crawl_progress[url] = {
				'status': 'crawled',
				'status_code': status_code,
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}

			# Determine file extension based on content type
			parsed_url = urlparse(url)
			path = parsed_url.path
			ext = self.get_file_extension_from_content_type(content_type, path)

			# Create filename
			filename = f"{len(self.crawled_pages):04d}_{path.replace('/', '_')}{ext}"
			filepath = os.path.join(self.temp_dir, filename)

			if status_code == 200:
				# Get content using streaming to avoid memory issues with large files
				response = make_http_request_with_retry('get', url, logger=self.logger, timeout=int(cfg.get('connections', 'timeout')), allow_redirects=True, headers=headers, stream=True)

				# For text content, we need to collect it for link extraction
				text_content = ""
				actual_size = 0
				if 'text/' in content_type or 'application/javascript' in content_type or 'application/css' in content_type:
					# Stream text content and collect it for link extraction
					with open(filepath, 'w', encoding='utf-8') as f:
						for chunk in response.iter_content(chunk_size=8192):
							if chunk:  # Filter out keep-alive chunks
								# Decode bytes to string if needed
								if isinstance(chunk, bytes):
									chunk = chunk.decode('utf-8', errors='ignore')
								f.write(chunk)
								text_content += chunk
								actual_size += len(chunk.encode('utf-8'))  # Count bytes, not characters
				else:
					# Stream binary content directly to file
					with open(filepath, 'wb') as f:
						for chunk in response.iter_content(chunk_size=8192):
							if chunk:  # Filter out keep-alive chunks
								f.write(chunk)
								actual_size += len(chunk)

				# Log the crawl with actual size
				if self.logger and actual_size > 0:
					self.logger.log_url_crawl(url, status_code, content_type, actual_size)

				# Extract links for further crawling
				# Always extract links from text content (HTML, CSS, JS) regardless of mode
				if 'text/' in content_type or 'application/javascript' in content_type or 'application/css' in content_type:
					links = self.extract_links(text_content, response.url)

					# Also extract links from CSS files
					if 'css' in content_type:
						css_links = self.extract_css_links(text_content, response.url)
						links.extend(css_links)

					new_links_count = 0
					for link in links:
						# Check if link should be ignored before adding to queue
						should_ignore, matching_pattern, description = should_ignore_url(link)
						if should_ignore:
							# Mark as skipped in progress
							crawl_progress[link] = {
								'status': 'skipped',
								'message': f'Skipped (matches pattern: {description or matching_pattern})',
								'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
							}
							self.visited_urls.add(link)
						elif link not in self.visited_urls and link not in self.to_visit:
							self.to_visit.append(link)
							new_links_count += 1

					# Update stats with newly discovered URLs
					if new_links_count > 0:
						crawl_stats[self.start_url]['total_discovered'] = len(self.visited_urls) + len(self.to_visit)
						# Log links discovery
						if self.logger:
							self.logger.log_links_discovered(url, new_links_count)
			else:
				# Make dummy file
				with open(filepath, 'w', encoding='utf-8') as f:
					f.write("")

			self.crawled_pages.append({
				'url': url,
				'filepath': filepath,
				'status_code': status_code,
				'content_type': content_type
			})

			self.visited_urls.add(url)
			return status_code

		except Exception as e:
			crawl_progress[url] = {
				'status': 'error',
				'error': str(e),
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}
			# Log the error
			if self.logger:
				self.logger.log_url_error(url, str(e))
			return None

	def crawl_page_wiki(self, url):
		"""
		Crawl MediaWiki sites efficiently by parsing from Special:AllPages.

		This method avoids recursively discovering links and instead
		only crawls the article pages listed in the Special:AllPages view.

		Args:
			url (str): The URL to crawl (usually the main page or Special:AllPages).
		"""
		try:
			headers = {
				"User-Agent": cfg.get('simple', 'user_agent'),
				"Accept": cfg.get('simple', 'accept_header'),
				"Accept-Language": cfg.get('simple', 'accept_language')
			}

			# Determine base wiki root
			parsed = urlparse(self.start_url)
			base_root = f"{parsed.scheme}://{parsed.netloc}"

			# Identify the Special:AllPages URL
			if "Special:AllPages" not in url:
				allpages_url = urljoin(base_root, "/wiki/Special:AllPages")
			else:
				allpages_url = url

			if self.logger:
				self.logger.log(f"Starting Wiki crawl from {allpages_url}", "INFO")

			all_article_links = set()
			next_page = allpages_url

			while next_page:
				self.logger.log(f"Processing wiki page: {next_page}", "DEBUG")
				resp = make_http_request_with_retry("get", next_page, logger=self.logger, headers=headers)
				if resp.status_code != 200:
					self.logger.log(f"Failed to fetch {next_page} (status {resp.status_code})", "ERROR")
					break

				soup = BeautifulSoup(resp.text, "html.parser")

				# Extract article links (skip Special:, Talk:, etc.)
				for a in soup.select("a[href^='/wiki/']"):

					href = a.get("href")
					if any(href.startswith(prefix) for prefix in [
						"/wiki/Special:",
						"/wiki/Talk:",
						"/wiki/User:",
						"/wiki/Help:",
						"/wiki/Category:",
						"/wiki/File:",
						"/wiki/Template:"
					]):
						continue
					full_url = urljoin(base_root, href)

					if not self.is_same_host(full_url):
						continue

					all_article_links.add(full_url)

				# Find "next page" link in pagination
				nav_div = soup.select_one("div.mw-allpages-nav")
				if nav_div:
					nav_links = nav_div.select("a[href*='from=']")
					if len(nav_links) > 1:
						next_link = nav_links[-1]
						next_page = urljoin(base_root, next_link["href"])
					elif next_page == allpages_url and len(nav_links) > 0:
						next_link = nav_links[-1]
						next_page = urljoin(base_root, next_link["href"])
					else:
						next_page = None
				else:
					next_page = None

			if self.logger:
				self.logger.log_links_discovered(allpages_url, len(all_article_links))

			# Now crawl each discovered article page (non-recursive)
			for article_url in sorted(all_article_links):
				if crawl_abort_flags.get(self.start_url, False):
					self.logger.log("Crawl aborted by user during Wiki crawl", "WARN")
					break

				is_valid, safe_article_url, err = validate_url(article_url)
				if not is_valid:
					if self.logger:
						self.logger.log(f"Skipping invalid wiki article URL: {err}", "WARN")
					continue
				article_url = safe_article_url

				should_ignore, pattern, description = should_ignore_url(article_url)
				if should_ignore:
					if self.logger:
						self.logger.log_url_skip(article_url, f"matches pattern: {description or pattern}")
					crawl_progress[article_url] = {
						'status': 'skipped',
						'message': f'Skipped (matches pattern: {description or pattern})',
						'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					}
					continue

				if article_url in self.visited_urls:
					continue

				self.visited_urls.add(article_url)
				crawl_progress[article_url] = {
					'status': 'crawling',
					'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				}

				try:
					head_resp = make_http_request_with_retry('head', article_url, logger=self.logger, headers=headers, allow_redirects=True)
					content_length = head_resp.headers.get('Content-Length')
					if self.max_size > 0 and content_length and int(content_length) > self.max_size:
						self.logger.log_url_skip(article_url, "skipped due to size limit")
						crawl_progress[article_url] = {
							'status': 'skipped',
							'message': 'Skipped (too large)',
							'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
						}
						continue

					# Perform a simple fetch similar to crawl_page but no recursion
					resp = make_http_request_with_retry("get", article_url, logger=self.logger, headers=headers)
					content_type = self.infer_content_type_from_url(article_url, resp.headers.get("content-type", ""))
					file_ext = self.get_file_extension_from_content_type(content_type, urlparse(article_url).path)

					safe_path = re.sub(r'[^a-zA-Z0-9._-]', '_', urlparse(article_url).path)
					filename = f"{len(self.crawled_pages):04d}_{safe_path}{file_ext}"
					filepath = os.path.join(self.temp_dir, filename)

					with open(filepath, 'wb') as f:
						f.write(resp.content)

					self.crawled_pages.append({
						"url": article_url,
						"filepath": filepath,
						"status_code": resp.status_code,
						"content_type": content_type
					})

					crawl_progress[article_url]['status'] = 'crawled'
					crawl_progress[article_url]['status_code'] = resp.status_code

					self.logger.log_url_crawl(article_url, resp.status_code, content_type, len(resp.content))

					if 'text/html' in content_type:
						# Extract media links
						text_content = resp.content.decode('utf-8', errors='ignore')
						media_links = self.extract_media_links(text_content, base_root)
						if self.logger:
							self.logger.log_links_discovered(article_url, len(media_links))

						for media_url in media_links:

							should_ignore, pattern, description = should_ignore_url(media_url)
							if should_ignore:
								continue

							if media_url not in self.visited_urls:
								self.visited_urls.add(media_url)
								self.crawl_page(media_url)

							time.sleep(0.5 if self.niceness else 0)

						# Extract CSS files
						css_links = self.extract_css_links(text_content, base_root)
						if self.logger:
							self.logger.log_links_discovered(article_url, len(css_links))

						for css_url in css_links:

							should_ignore, pattern, description = should_ignore_url(css_url)
							if should_ignore:
								continue

							if css_url not in self.visited_urls:
								self.visited_urls.add(css_url)
								self.crawl_page(css_url)

							time.sleep(0.5 if self.niceness else 0)

				except Exception as e:
					self.logger.log_url_error(article_url, str(e))
					crawl_progress[article_url] = {
						'status': 'error',
						'error': str(e),
						'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					}

			if self.logger:
				self.logger.log(f"Wiki crawl completed. {len(self.crawled_pages)} pages archived.", "INFO")
			return 200 if self.crawled_pages else 204

		except Exception as e:
			self.logger.log_crawl_error(f"Wiki crawl failed: {str(e)}")
			traceback.print_exception(type(e), e, e.__traceback__)
			return None

	def create_warc_archive(self):
		"""
		Create a WARC archive from all crawled pages.

		Returns:
			str: Path to the created WARC file
		"""
		warc_dir = cfg.get('general', 'archives_dir')
		os.makedirs(warc_dir, exist_ok=True)

		# Extract hostname from start URL
		hostname = urlparse(self.start_url).netloc
		# Remove port if present
		if ':' in hostname:
			hostname = hostname.split(':')[0]

		warc_filename = f"temp_{hostname}.warc"
		warc_path = os.path.join(warc_dir, warc_filename)

		# Log WARC creation start
		if self.logger:
			self.logger.log(f"Total pages to archive: {len(self.crawled_pages)}")
		with open(warc_path, 'wb') as output:
			writer = WARCWriter(output, gzip=True)

			for page in self.crawled_pages:
				# Read content based on file type
				content_type = page['content_type']
				if 'text/' in content_type or 'application/javascript' in content_type or 'application/css' in content_type:
					with open(page['filepath'], 'r', encoding='utf-8') as f:
						content = f.read().encode('utf-8')
				else:
					with open(page['filepath'], 'rb') as f:
						content = f.read()

				# Create WARC record with proper HTTP response format
				http_headers = f"HTTP/1.1 {page['status_code']} OK\r\n"
				http_headers += f"Content-Type: {content_type}\r\n"
				http_headers += f"Content-Length: {len(content)}\r\n"
				http_headers += "\r\n"

				# Combine headers and content
				payload = http_headers.encode('utf-8') + content

				# Create a BytesIO object to make it file-like
				payload_stream = BytesIO(payload)

				# Create WARC record
				record = writer.create_warc_record(
					uri=page['url'],
					record_type='response',
					payload=payload_stream
				)
				writer.write_record(record)

		# Log WARC file completion with size
		if self.logger and os.path.exists(warc_path):
			warc_size = os.path.getsize(warc_path)
			self.logger.log(f"Pages archived successfully: {warc_path} ({warc_size:,} bytes)")

		return warc_path

	def crawl(self):
		"""
		Main crawling function that orchestrates the entire crawling process.

		This method handles the crawling loop, creates the WARC archive,
		and saves the results to the database.
		"""
		self.start_time = int(time.time())

		self.temp_dir = "{}/crawler_{}".format(cfg.get('general', 'temp_dir'), threading.get_ident())
		os.makedirs(self.temp_dir, exist_ok=True)

		# Create log file path (will be alongside the WARC file)
		warc_dir = cfg.get('general', 'archives_dir')
		os.makedirs(warc_dir, exist_ok=True)
		hostname = urlparse(self.start_url).netloc
		if ':' in hostname:
			hostname = hostname.split(':')[0]
		log_filename = f"temp_{hostname}.log"
		log_path = os.path.join(warc_dir, log_filename)

		# Initialize logger
		self.logger = CrawlLogger(log_path)
		self.logger.log_crawl_start(self.start_url, self.mode, self.max_size, self.niceness, self.restrictpage)

		# Initialize WebDriver for Advanced mode
		if self.mode == 'advanced':
			if not SELENIUM_AVAILABLE:
				self.logger.log("Selenium not available. Falling back to Simple mode.", "WARN")
				self.mode = 'simple'
			else:
				try:
					self.driver = create_webdriver()
					self.logger.log("WebDriver initialized for Advanced mode", "INFO")
				except Exception as e:
					self.logger.log(f"Failed to initialize WebDriver: {str(e)}. Falling back to Simple mode.", "ERROR")
					self.mode = 'simple'

		# Initialize crawl stats
		crawl_stats[self.start_url] = {
			'total_discovered': 0,
			'total_completed': 0,
			'status': 'running'
		}

		try:
			while self.to_visit:
				# Check if crawl should be aborted
				if crawl_abort_flags.get(self.start_url, False):
					self.logger.log("Crawl aborted by user", "WARN")
					crawl_stats[self.start_url]['status'] = 'aborted'
					# Clean up WebDriver if used
					if self.driver:
						try:
							self.driver.quit()
							self.logger.log("WebDriver closed after abort", "INFO")
						except Exception as e:
							self.logger.log(f"Error closing WebDriver after abort: {str(e)}", "WARN")
					# Clean up temp directory
					if self.temp_dir and os.path.exists(self.temp_dir):
						shutil.rmtree(self.temp_dir)

					# Clear global state for this crawl after abort
					clear_crawl_state(self.start_url)
					return

				url = self.to_visit.pop(0)
				if url not in self.visited_urls:
					crawl_progress[url] = {
						'status': 'crawling',
						'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					}
					# Use appropriate crawling method based on mode
					if self.mode == 'advanced' and self.driver:
						self.crawl_page_selenium(url)
					elif self.mode == 'wiki':
						self.crawl_page_wiki(url)
					else:
						self.crawl_page(url)

					# Update stats
					crawl_stats[self.start_url]['total_completed'] = len(self.visited_urls)
					crawl_stats[self.start_url]['total_discovered'] = len(self.visited_urls) + len(self.to_visit)

					# Be respectful to the server (unless niceness is disabled)
					if self.niceness:
						time.sleep(0.5)

			self.warc_file = self.create_warc_archive()

			# Check if any page were archived
			status = 'completed'
			if len(self.crawled_pages) == 0:
				status = 'error: no page crawled.'

			# Save to database
			conn = sqlite3.connect(cfg.get('general', 'db_file'))
			cursor = conn.cursor()
			cursor.execute('''
				INSERT INTO archives (url, mode, warc_file, log_file, pages_crawled, status, crawl_time, max_size)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			''', (self.start_url, self.mode, self.warc_file, self.logger.log_file_path, len(self.crawled_pages), status, (int(time.time()) - self.start_time), self.max_size))
			archive_id = cursor.lastrowid
			conn.commit()
			conn.close()

			# Rename WARC file with proper ID
			hostname = urlparse(self.start_url).netloc
			if ':' in hostname:
				hostname = hostname.split(':')[0]
			new_filename = f"{archive_id:04d}_{hostname}.warc"
			new_path = os.path.join(os.path.dirname(self.warc_file), new_filename)
			os.rename(self.warc_file, new_path)
			self.warc_file = new_path

			# Also rename the log file
			if hasattr(self, 'logger') and self.logger:
				log_filename = f"{archive_id:04d}_{hostname}.log"
				log_new_path = os.path.join(os.path.dirname(self.logger.log_file_path), log_filename)
				os.rename(self.logger.log_file_path, log_new_path)
				self.logger.log_file_path = log_new_path

			# Update database with new filename
			conn = sqlite3.connect(cfg.get('general', 'db_file'))
			cursor = conn.cursor()
			cursor.execute('UPDATE archives SET warc_file = ?, log_file = ? WHERE id = ?', (self.warc_file, self.logger.log_file_path, archive_id))
			conn.commit()
			conn.close()

			# Mark crawl as completed
			crawl_stats[self.start_url]['status'] = 'completed'
			crawl_stats[self.start_url]['total_completed'] = len(self.crawled_pages)
			crawl_stats[self.start_url]['total_discovered'] = len(self.crawled_pages)

			# Log completion
			self.logger.log_crawl_complete(len(self.crawled_pages), (int(time.time()) - self.start_time), self.warc_file)

			# Clean up WebDriver if used
			if self.driver:
				try:
					self.driver.quit()
					self.logger.log("WebDriver closed successfully", "INFO")
				except Exception as e:
					self.logger.log(f"Error closing WebDriver: {str(e)}", "WARN")

			# Clean up temp directory
			shutil.rmtree(self.temp_dir)

			# Clear global state for this crawl after successful completion
			clear_crawl_state(self.start_url)

		except Exception as e:
			# Update status to error
			traceback.print_exception(type(e), e, e.__traceback__, file=sys.stderr)
			print("[ERROR] Crawl thread failed. Cleaning up.", file=sys.stderr)

			# Log the error if logger is available
			if hasattr(self, 'logger') and self.logger:
				self.logger.log_crawl_error(str(e))
			conn = sqlite3.connect(cfg.get('general', 'db_file'))
			cursor = conn.cursor()
			log_file_path = self.logger.log_file_path if hasattr(self, 'logger') and self.logger else ''
			cursor.execute('''
				INSERT INTO archives (url, mode, warc_file, log_file, pages_crawled, status, crawl_time, max_size)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			''', (self.start_url, self.mode, '', log_file_path, 0, f'error: {str(e)}', (int(time.time()) - self.start_time), self.max_size))
			conn.commit()
			conn.close()

			# Clean up WebDriver if used
			if hasattr(self, 'driver') and self.driver:
				try:
					self.driver.quit()
				except Exception:
					pass  # Ignore errors during cleanup

			if self.temp_dir and os.path.exists(self.temp_dir):
				shutil.rmtree(self.temp_dir)

			# Clear global state for this crawl after error
			clear_crawl_state(self.start_url)

@app.route('/')
@login_required
def index():
	"""
	Main page route that displays the crawler interface and list of archives.

	Returns:
		Rendered HTML template with archives data
	"""
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT * FROM archives ORDER BY created_at DESC')
	archives = cursor.fetchall()
	conn.close()
	return render_template('crawler.html', archives=archives)

@app.route('/start_crawl', methods=['POST'])
@login_required
def start_crawl():
	"""
	Start a new web crawl with input validation and security checks.

	Returns:
		JSON response with crawl status or error message
	"""
	# Get and validate URL
	url = request.form.get('url')
	is_valid, sanitized_url, error_msg = validate_url(url)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Validate mode
	mode = request.form.get('mode', 'simple')
	if mode not in ['simple', 'advanced', 'wiki']:
		mode = 'simple'  # Default to safe mode

	# Validate max_size
	try:
		max_size = int(request.form.get('max_size', '0'))
		if max_size < 0 or max_size > 1000 * 1024 * 1024:  # Max 1GB
			max_size = 0
	except (ValueError, TypeError):
		max_size = 0

	# Validate boolean options
	niceness = request.form.get('niceness', 'true').lower() == 'true'
	restrictpage = request.form.get('restrictpage', 'true').lower() == 'true'

	# Clear any existing state for this URL before starting new crawl
	clear_crawl_state(sanitized_url)

	# Start crawling in a separate thread
	crawler = WebCrawler(sanitized_url, mode, max_size, niceness, restrictpage)
	thread = threading.Thread(target=crawler.crawl)
	thread.daemon = True
	thread.start()

	return jsonify({'message': 'Crawl started', 'url': sanitized_url, 'mode': mode, 'max_size': max_size, 'niceness': niceness, 'restrictpage': restrictpage})

@app.route('/progress')
@login_required
def get_progress():
	"""
	Get current crawl progress information for all active crawls.

	Returns:
		JSON response containing individual URL progress and overall statistics
	"""
	return jsonify({
		'individual': crawl_progress,
		'stats': crawl_stats
	})

@app.route('/active_crawls')
@login_required
def get_active_crawls():
	"""
	Get information about currently active crawls.

	Returns:
		JSON response with active crawl information
	"""
	active_crawls = []

	for url, stats in crawl_stats.items():
		if stats.get('status') in ['running']:
			# Get progress for this crawl
			crawl_progress_data = {}
			for progress_url, progress_data in crawl_progress.items():
				if progress_url.startswith(url) or url in progress_url:
					crawl_progress_data[progress_url] = progress_data

			active_crawls.append({
				'url': url,
				'stats': stats,
				'progress': crawl_progress_data
			})

	return jsonify({
		'active_crawls': active_crawls,
		'has_active_crawls': len(active_crawls) > 0
	})

@app.route('/abort_crawl', methods=['POST'])
@login_required
def abort_crawl():
	"""
	Abort an ongoing crawl process.

	Returns:
		JSON response with abort status or error message
	"""
	url = request.form.get('url')
	if not url:
		return jsonify({'error': 'URL is required'}), 400

	# Validate URL format
	is_valid, sanitized_url, error_msg = validate_url(url)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Set abort flag for this URL
	crawl_abort_flags[sanitized_url] = True

	# Update crawl stats to show aborted status
	if sanitized_url in crawl_stats:
		crawl_stats[sanitized_url]['status'] = 'aborted'

	return jsonify({'message': 'Crawl abort requested', 'url': url})

@app.route('/delete/<int:archive_id>', methods=['POST'])
@login_required
def delete_entry(archive_id):
	"""
	Start archive deletion in background with input validation.

	Args:
		archive_id (int): The archive ID to delete

	Returns:
		JSON response with deletion status or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Check if archive exists
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT id FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive:
		return jsonify({'error': 'Archive not found'}), 404

	# Initialize delete status
	delete_status[sanitized_id] = {
		'status': 'starting',
		'message': 'Preparing deletion...',
		'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	}

	# Start deletion in background thread
	thread = threading.Thread(target=delete_worker, args=(sanitized_id,))
	thread.daemon = True
	thread.start()

	return jsonify({'message': 'Deletion started', 'archive_id': sanitized_id})

@app.route('/delete_status/<int:archive_id>')
@login_required
def delete_status_check(archive_id):
	"""
	Get archive deletion status with input validation.

	Args:
		archive_id (int): The archive ID to check deletion status for

	Returns:
		JSON response with deletion status or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Clean up old entries periodically
	cleanup_old_delete_status()

	if sanitized_id in delete_status:
		return jsonify(delete_status[sanitized_id])
	else:
		return jsonify({'status': 'not_found', 'message': 'No deletion found for this archive'}), 404

# Global variables to store upload and delete status
upload_status = {}
delete_status = {}

def cleanup_old_upload_status():
	"""
	Clean up upload status entries older than 1 hour to prevent memory leaks.

	Removes entries from the global upload_status dictionary that are older than 1 hour
	or have invalid timestamps.
	"""
	current_time = datetime.now()
	to_remove = []

	for archive_id, status_data in upload_status.items():
		if 'timestamp' in status_data:
			try:
				status_time = datetime.strptime(status_data['timestamp'], '%Y-%m-%d %H:%M:%S')
				if (current_time - status_time).total_seconds() > 3600:  # 1 hour
					to_remove.append(archive_id)
			except:
				# If timestamp parsing fails, remove the entry
				to_remove.append(archive_id)

	for archive_id in to_remove:
		del upload_status[archive_id]

def cleanup_old_delete_status():
	"""
	Clean up delete status entries older than 1 hour to prevent memory leaks.

	Removes entries from the global delete_status dictionary that are older than 1 hour
	or have invalid timestamps.
	"""
	current_time = datetime.now()
	to_remove = []

	for archive_id, status_data in delete_status.items():
		if 'timestamp' in status_data:
			try:
				status_time = datetime.strptime(status_data['timestamp'], '%Y-%m-%d %H:%M:%S')
				if (current_time - status_time).total_seconds() > 3600:  # 1 hour
					to_remove.append(archive_id)
			except:
				# If timestamp parsing fails, remove the entry
				to_remove.append(archive_id)

	for archive_id in to_remove:
		del delete_status[archive_id]

def delete_worker(archive_id):
	"""
	Worker function to handle archive deletion in background thread.

	Args:
		archive_id (int): The archive ID to delete

	Updates the global delete_status dictionary with progress and results.
	"""
	try:
		# Update status to deleting
		delete_status[archive_id] = {
			'status': 'deleting',
			'message': 'Deleting archive and associated files...',
			'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		}

		# Get archive information
		conn = sqlite3.connect(cfg.get('general', 'db_file'))
		cursor = conn.cursor()
		cursor.execute('SELECT warc_file, log_file FROM archives WHERE id = ?', (archive_id,))
		archive = cursor.fetchone()

		if not archive:
			delete_status[archive_id] = {
				'status': 'error',
				'message': 'Archive not found in database',
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}
			conn.close()
			return

		warc_file = archive[0]
		log_file = archive[1] if len(archive) > 1 else None

		# Delete WARC file if it exists
		warc_deleted = False
		if warc_file and warc_file != "" and os.path.exists(warc_file):
			try:
				subprocess.run(["rm", "-f", warc_file], check=True)
				warc_deleted = True
			except Exception as e:
				# Log the error but continue with database deletion
				print(f"[ERROR] Error deleting WARC file {warc_file}: {str(e)}\n", file=sys.stderr)

		# Delete log file if it exists
		log_deleted = False
		if log_file and log_file != "" and os.path.exists(log_file):
			try:
				subprocess.run(["rm", "-f", log_file], check=True)
				log_deleted = True
			except Exception as e:
				# Log the error but continue with database deletion
				print(f"[ERROR] Error deleting log file {log_file}: {str(e)}\n", file=sys.stderr)

		# Delete from database
		cursor.execute('DELETE FROM archives WHERE id = ?', (archive_id,))
		conn.commit()
		conn.close()

		# Update status to success
		files_info = []
		if warc_deleted:
			files_info.append("WARC file removed")
		elif warc_file and warc_file != "":
			files_info.append("WARC file not found")

		if log_deleted:
			files_info.append("log file removed")
		elif log_file and log_file != "":
			files_info.append("log file not found")

		files_message = f" ({', '.join(files_info)})" if files_info else ""

		delete_status[archive_id] = {
			'status': 'success',
			'message': f'Archive successfully deleted{files_message}',
			'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		}

		# Log success
		print(f"[INFO] Archive {archive_id} successfully deleted\n", file=sys.stderr)

	except Exception as e:
		# Update status to error
		delete_status[archive_id] = {
			'status': 'error',
			'message': f'Delete error: {str(e)}',
			'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		}

		# Log error
		print(f"[ERROR] Archive deletion error for archive {archive_id}: {str(e)}\n", file=sys.stderr)

def ia_upload_worker(archive_id, title, description, warc_file):
	"""
	Worker function to handle Internet Archive upload in background thread.

	Args:
		archive_id (int): The archive ID being uploaded
		title (str): Sanitized title for the upload
		description (str): Sanitized description for the upload
		warc_file (str): Path to the WARC file to upload

	Updates the global upload_status dictionary with progress and results.
	"""
	try:
		# Prepare metadata for Internet Archive upload
		metadata = {
			'mediatype': 'web',
			'title': sanitize_metadata_field(title),
			'description': sanitize_metadata_field(description),
			'creator': 'Web Crawler'
		}

		# Get the identifier from the filename (without extension)
		identifier = os.path.splitext(warc_file.split('/')[-1])[0]

		# Update status to uploading
		upload_status[archive_id] = {
			'status': 'uploading',
			'message': 'Starting upload to Internet Archive...',
			'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		}

		# Upload using the Internet Archive Python module
		response = upload(identifier, [warc_file], metadata=metadata)

		# Check response and update status
		if response[0].status_code == 200:
			upload_status[archive_id] = {
				'status': 'success',
				'message': f'Successfully uploaded to Internet Archive with identifier: {identifier}',
				'identifier': identifier,
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}

			# Log success
			print(f"[INFO] Internet Archive upload successful for {identifier}\n", file=sys.stderr)
		else:
			upload_status[archive_id] = {
				'status': 'error',
				'message': f'Upload failed with status code: {response[0].status_code}',
				'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			}

			# Log failure
			print(f"[ERROR] Internet Archive upload failed for {identifier} with status code: {response[0].status_code}\n", file=sys.stderr)

	except Exception as e:
		# Update status to error
		upload_status[archive_id] = {
			'status': 'error',
			'message': f'Upload error: {str(e)}',
			'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		}

		# Log error
		print(f"[ERROR] Internet Archive upload error for archive {archive_id}: {str(e)}\n", file=sys.stderr)

@app.route('/ia/<int:archive_id>', methods=['POST'])
@login_required
def ia_upload(archive_id):
	"""
	Start Internet Archive upload in background with input validation.

	Args:
		archive_id (int): The archive ID to upload

	Returns:
		JSON response with upload status or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Get and validate JSON data
	data = request.get_json()
	if not data:
		return jsonify({'error': 'JSON data is required'}), 400

	if 'title' not in data or 'description' not in data:
		return jsonify({'error': 'Title and description are required'}), 400

	# Sanitize title and description
	title = sanitize_metadata_field(data['title'])
	description = sanitize_metadata_field(data['description'])

	if not title or not description:
		return jsonify({'error': 'Title and description cannot be empty'}), 400

	# Check if archive exists
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT warc_file FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive or not archive[0] or not os.path.exists(archive[0]):
		return jsonify({'error': 'Archive file not found'}), 404

	# Initialize upload status
	upload_status[sanitized_id] = {
		'status': 'starting',
		'message': 'Preparing upload...',
		'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	}

	# Start upload in background thread
	thread = threading.Thread(
		target=ia_upload_worker,
		args=(sanitized_id, title, description, archive[0])
	)
	thread.daemon = True
	thread.start()

	return jsonify({'message': 'Upload started', 'archive_id': sanitized_id})

@app.route('/ia_status/<int:archive_id>')
@login_required
def ia_upload_status(archive_id):
	"""
	Get Internet Archive upload status with input validation.

	Args:
		archive_id (int): The archive ID to check status for

	Returns:
		JSON response with upload status or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Clean up old entries periodically
	cleanup_old_upload_status()

	if sanitized_id in upload_status:
		return jsonify(upload_status[sanitized_id])
	else:
		return jsonify({'status': 'not_found', 'message': 'No upload found for this archive'}), 404

@app.route('/archive_details/<int:archive_id>')
@login_required
def archive_details(archive_id):
	"""
	Get detailed information about a specific archive.

	Args:
		archive_id (int): The archive ID to get details for

	Returns:
		JSON response with archive details or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT * FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive:
		return jsonify({'error': 'Archive not found'}), 404

	# Return JSON details
	details = {
		'id': archive[0],
		'url': archive[1],
		'mode': archive[2],
		'created_at': archive[3],
		'warc_file': archive[4],
		'log_file': archive[5],
		'pages_crawled': archive[6],
		'status': archive[7],
		'crawl_time': archive[8],
		'max_size': archive[9]
	}

	return jsonify(details)

@app.route('/log_file/<int:archive_id>')
@login_required
def get_log_file(archive_id):
	"""
	Get the log file content for a specific archive.

	Args:
		archive_id (int): The archive ID to get log file for

	Returns:
		JSON response with log content or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT log_file FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive or not archive[0]:
		return jsonify({'error': 'Log file not found for this archive'}), 404

	log_file_path = archive[0]
	if not os.path.exists(log_file_path):
		return jsonify({'error': 'Log file does not exist on disk'}), 404

	try:
		with open(log_file_path, 'r', encoding='utf-8') as f:
			log_content = f.read()

		return jsonify({
			'log_content': log_content,
			'log_file': log_file_path,
			'archive_id': sanitized_id
		})
	except Exception as e:
		return jsonify({'error': f'Error reading log file: {str(e)}'}), 500

@app.route('/view_archive/<int:archive_id>')
@login_required
def view_archive(archive_id):
	"""
	Display a WARC archive viewer with list of all records in the archive.

	Args:
		archive_id (int): The archive ID to view

	Returns:
		Rendered HTML template with archive records or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return f"Invalid archive ID: {error_msg}", 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT * FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive:
		return "Archive not found", 404

	warc_file = archive[4]  # warc_file is at index 4
	if not os.path.exists(warc_file):
		return f"WARC file not found: {warc_file}", 404

	# Read WARC file and extract record metadata (without content)
	records = []
	try:
		with open(warc_file, 'rb') as stream:
			for i, record in enumerate(ArchiveIterator(stream)):
				if record.rec_type == 'response':
					record_info = {
						'index': i,
						'url': record.rec_headers.get_header('WARC-Target-URI'),
						'content_type': record.http_headers.get_header('Content-Type', 'unknown'),
						'status_code': int(record.http_headers.get_statuscode() or 0),
						'content_length': record.rec_headers.get_header('Content-Length', '0'),
						'date': record.rec_headers.get_header('WARC-Date')
					}
					records.append(record_info)
	except Exception as e:
		return f"Error reading WARC file: {str(e)}", 500

	return render_template('warc_viewer.html', archive=archive, records=records)

@app.route('/view_file/<int:archive_id>/<int:record_index>')
@login_required
def view_file(archive_id, record_index):
	"""
	View a specific file/record from a WARC archive with URL rewriting.

	Args:
		archive_id (int): The archive ID containing the record
		record_index (int): The index of the record to view

	Returns:
		Rendered HTML template with file content or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return f"Invalid archive ID: {error_msg}", 400

	# Validate record index
	try:
		record_index = int(record_index)
		if record_index < 0:
			return "Invalid record index", 400
	except (ValueError, TypeError):
		return "Invalid record index format", 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT * FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive:
		return "Archive not found", 404

	warc_file = archive[4]  # warc_file is at index 4
	if not os.path.exists(warc_file):
		return f"WARC file not found: {warc_file}", 404

	# Find the specific record by index
	try:
		with open(warc_file, 'rb') as stream:
			for i, record in enumerate(ArchiveIterator(stream)):
				if record.rec_type == 'response' and i == record_index:
					content_bytes = record.content_stream().read()
					content_type = record.http_headers.get_header('Content-Type', 'text/html')
					url = record.rec_headers.get_header('WARC-Target-URI')
					status_code = int(record.http_headers.get_statuscode() or 0)

					# Handle content based on type
					content_size = len(content_bytes)
					content = None
					is_large_binary = False

					if content_type.startswith('text/') or content_type.startswith('application/javascript') or content_type.startswith('application/css'):
						# Text content - decode as UTF-8
						content = content_bytes.decode('utf-8', errors='ignore')

						# For HTML and CSS content, rewrite URLs to point to archived files
						if content_type.startswith('text/html'):
							content = rewrite_html_urls(content, sanitized_id, url)
						elif content_type.startswith('text/css'):
							content = rewrite_css_urls(content, sanitized_id, url)
					elif content_type.startswith('image/'):
						# Images - encode as base64 for display (but only if not too large)
						max_image_size = int(cfg.get('viewer', 'max_image_display_size'))
						if content_size <= max_image_size:
							content = base64.b64encode(content_bytes).decode('utf-8')
						else:
							is_large_binary = True
					else:
						# Other binary content - only encode if small, otherwise just show a download button
						max_binary_size = int(cfg.get('viewer', 'max_binary_display_size'))
						if content_size <= max_binary_size:
							content = base64.b64encode(content_bytes).decode('utf-8')
						else:
							is_large_binary = True

					return render_template('file_viewer.html',
						content=content,
						content_type=content_type,
						url=url,
						status_code=status_code,
						archive_id=sanitized_id,
						content_size=content_size,
						is_large_binary=is_large_binary)

		return "Record not found", 404
	except Exception as e:
		return f"Error reading WARC file: {str(e)}", 500

@app.route('/raw_file/<int:archive_id>/<int:record_index>')
@login_required
def raw_file(archive_id, record_index):
	"""
	Serve raw file content from a WARC archive record with proper MIME types.

	Args:
		archive_id (int): The archive ID containing the record
		record_index (int): The index of the record to serve

	Returns:
		Flask Response with file content and proper MIME type or error message
	"""
	# Validate archive ID
	is_valid, sanitized_id, error_msg = validate_archive_id(archive_id)
	if not is_valid:
		return f"Invalid archive ID: {error_msg}", 400

	# Validate record index
	try:
		record_index = int(record_index)
		if record_index < 0:
			return "Invalid record index", 400
	except (ValueError, TypeError):
		return "Invalid record index format", 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT * FROM archives WHERE id = ?', (sanitized_id,))
	archive = cursor.fetchone()
	conn.close()

	if not archive:
		return "Archive not found", 404

	warc_file = archive[4]  # warc_file is at index 4
	if not os.path.exists(warc_file):
		return f"WARC file not found: {warc_file}", 404

	# Find the specific record by index
	try:
		with open(warc_file, 'rb') as stream:
			for i, record in enumerate(ArchiveIterator(stream)):
				if record.rec_type == 'response' and i == record_index:
					content_bytes = record.content_stream().read()
					content_type = record.http_headers.get_header('Content-Type', 'text/html')

					# Create response with proper content type
					from flask import Response

					# Handle content based on type
					if content_type.startswith('text/') or content_type.startswith('application/javascript') or content_type.startswith('application/css'):
						# Text content - decode as UTF-8
						content = content_bytes.decode('utf-8', errors='ignore')

						# For HTML and CSS content, rewrite URLs to point to archived files
						if content_type.startswith('text/html'):
							content = rewrite_html_urls(content, sanitized_id, record.rec_headers.get_header('WARC-Target-URI'))
						elif content_type.startswith('text/css'):
							content = rewrite_css_urls(content, sanitized_id, record.rec_headers.get_header('WARC-Target-URI'))

						return Response(content, mimetype=content_type)
					else:
						# Binary content - serve directly
						return Response(content_bytes, mimetype=content_type)

		return "Record not found", 404
	except Exception as e:
		return f"Error reading WARC file: {str(e)}", 500

@app.route('/ignore_patterns')
@login_required
def get_ignore_patterns():
	"""
	Get all ignore patterns for URL exclusion.

	Returns:
		JSON response with list of ignore patterns
	"""
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT id, pattern, description, enabled, created_at FROM ignore_patterns ORDER BY created_at DESC')
	patterns = cursor.fetchall()
	conn.close()

	pattern_list = []
	for pattern in patterns:
		pattern_list.append({
			'id': pattern[0],
			'pattern': pattern[1],
			'description': pattern[2],
			'enabled': bool(pattern[3]),
			'created_at': pattern[4]
		})

	return jsonify({'patterns': pattern_list})

@app.route('/ignore_patterns', methods=['POST'])
@login_required
def add_ignore_pattern():
	"""
	Add a new ignore pattern with validation.

	Returns:
		JSON response with success/error message
	"""
	data = request.get_json()

	if not data or 'pattern' not in data:
		return jsonify({'error': 'Pattern is required'}), 400

	pattern = data['pattern'].strip()
	description = data.get('description', '').strip()

	# Validate pattern
	is_valid, error_msg = validate_regex_pattern(pattern)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	# Check if pattern already exists
	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()
	cursor.execute('SELECT id FROM ignore_patterns WHERE pattern = ?', (pattern,))
	if cursor.fetchone():
		conn.close()
		return jsonify({'error': 'Pattern already exists'}), 400

	# Insert new pattern
	cursor.execute('''
		INSERT INTO ignore_patterns (pattern, description) VALUES (?, ?)
	''', (pattern, description))
	pattern_id = cursor.lastrowid
	conn.commit()
	conn.close()

	return jsonify({'message': 'Pattern added successfully', 'id': pattern_id})

@app.route('/ignore_patterns/<int:pattern_id>', methods=['PUT'])
@login_required
def update_ignore_pattern(pattern_id):
	"""
	Update an existing ignore pattern.

	Args:
		pattern_id (int): The pattern ID to update

	Returns:
		JSON response with success/error message
	"""
	# Validate pattern ID
	is_valid, sanitized_id, error_msg = validate_archive_id(pattern_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	data = request.get_json()
	if not data:
		return jsonify({'error': 'JSON data is required'}), 400

	pattern = data.get('pattern', '').strip()
	description = data.get('description', '').strip()
	enabled = data.get('enabled', True)

	# Validate pattern if provided
	if pattern:
		is_valid, error_msg = validate_regex_pattern(pattern)
		if not is_valid:
			return jsonify({'error': error_msg}), 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()

	# Check if pattern exists
	cursor.execute('SELECT id FROM ignore_patterns WHERE id = ?', (sanitized_id,))
	if not cursor.fetchone():
		conn.close()
		return jsonify({'error': 'Pattern not found'}), 404

	# Check if new pattern already exists (if pattern is being changed)
	if pattern:
		cursor.execute('SELECT id FROM ignore_patterns WHERE pattern = ? AND id != ?', (pattern, sanitized_id))
		if cursor.fetchone():
			conn.close()
			return jsonify({'error': 'Pattern already exists'}), 400

	# Update pattern
	update_fields = []
	update_values = []

	if pattern:
		update_fields.append('pattern = ?')
		update_values.append(pattern)

	if 'description' in data:
		update_fields.append('description = ?')
		update_values.append(description)

	if 'enabled' in data:
		update_fields.append('enabled = ?')
		update_values.append(1 if enabled else 0)

	if update_fields:
		update_values.append(sanitized_id)
		query = f"UPDATE ignore_patterns SET {', '.join(update_fields)} WHERE id = ?"
		cursor.execute(query, update_values)

	conn.commit()
	conn.close()

	return jsonify({'message': 'Pattern updated successfully'})

@app.route('/ignore_patterns/<int:pattern_id>', methods=['DELETE'])
@login_required
def delete_ignore_pattern(pattern_id):
	"""
	Delete an ignore pattern.

	Args:
		pattern_id (int): The pattern ID to delete

	Returns:
		JSON response with success/error message
	"""
	# Validate pattern ID
	is_valid, sanitized_id, error_msg = validate_archive_id(pattern_id)
	if not is_valid:
		return jsonify({'error': error_msg}), 400

	conn = sqlite3.connect(cfg.get('general', 'db_file'))
	cursor = conn.cursor()

	# Check if pattern exists
	cursor.execute('SELECT id FROM ignore_patterns WHERE id = ?', (sanitized_id,))
	if not cursor.fetchone():
		conn.close()
		return jsonify({'error': 'Pattern not found'}), 404

	# Delete pattern
	cursor.execute('DELETE FROM ignore_patterns WHERE id = ?', (sanitized_id,))
	conn.commit()
	conn.close()

	return jsonify({'message': 'Pattern deleted successfully'})

@app.after_request
def changeserver(response):
	"""
	Modify HTTP response headers to hide server information for security.

	Args:
		response: Flask response object

	Returns:
		Modified response with updated Server header
	"""
	response.headers['Server'] = "Unknown"
	return response

if __name__ == '__main__':
	# Parse command line arguments
	import argparse
	parser = argparse.ArgumentParser(description='Web Crawler Application')
	parser.add_argument('--config', '-c', help='Path to configuration file', default='/opt/crawler/config/crawler.cfg')
	args = parser.parse_args()

	cfg = load_config(args.config)
	init_db()

	# Set Flask secret key from config
	app.config['SECRET_KEY'] = cfg.get('general', 'secret_key')

	ssl_cert = cfg.get('general', 'ssl_cert')
	ssl_key = cfg.get('general', 'ssl_key')

	# Only use SSL if both cert and key are provided and not empty
	ssl_context = None
	if ssl_cert and ssl_key and ssl_cert.strip() and ssl_key.strip():
		# Check if both files actually exist
		if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
			ssl_context = (ssl_cert, ssl_key)
		else:
			print(f"Warning: SSL certificate or key file not found. SSL disabled.", file=sys.stderr)

	app.run(
		host=cfg.get('general', 'ip_address'),
		port=int(cfg.get('general', 'port')),
		ssl_context=ssl_context,
		threaded=True
	)
