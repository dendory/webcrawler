#!/usr/bin/python3
# This web app provides a WARC viewer and a web archiver

import re
import os
import sys
import time
import base64
import shutil
import subprocess
import logging
import sqlite3
import requests
import threading
import traceback
from io import BytesIO
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urljoin, urlparse
from flask import Flask, render_template, request, jsonify, redirect, url_for, render_template_string
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter
from internetarchive import upload
from version import __version__

app = Flask(__name__)

class CrawlLogger:
	"""
	A logging class that writes crawl progress and information to a log file.
	"""

	def __init__(self, log_file_path):
		"""
		Initialize the logger with a log file path.

		Args:
			log_file_path (str): Path to the log file
		"""
		self.log_file_path = log_file_path
		self.lock = threading.Lock()

		# Create log file and write initial header
		with open(self.log_file_path, 'w', encoding='utf-8') as f:
			f.write(f"=== Web Crawler Log ===\n")
			f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
			f.write(f"Log file: {log_file_path}\n")
			f.write("=" * 50 + "\n\n")

	def log(self, message, level="INFO"):
		"""
		Log a message with timestamp and level.

		Args:
			message (str): The message to log
			level (str): Log level (INFO, WARN, ERROR, DEBUG)
		"""
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
			self.log(f"Discovered {links_count} new links from: {url}")

	def log_warc_creation(self, warc_path, pages_count):
		"""
		Log WARC file creation.

		Args:
			warc_path (str): Path to the created WARC file
			pages_count (int): Number of pages in the WARC
		"""
		self.log(f"Creating WARC file: {warc_path}")
		self.log(f"Total pages to archive: {pages_count}")

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
		self.log(f"WARC file created: {warc_path}")
		self.log(f"Log file: {self.log_file_path}")

	def log_crawl_error(self, error):
		"""
		Log crawl error.

		Args:
			error (str): Error message
		"""
		self.log(f"Crawl failed: {error}", "ERROR")
		self.log(f"Log file: {self.log_file_path}")

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
		return False, None, "URL too long"

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
	conn = sqlite3.connect('/data/db/crawler.db')
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
	default_file = os.path.join(os.path.dirname(__file__), 'default_ignores.tsv')

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
					print(f"[WARN]  Invalid pattern in default_ignores.tsv line {line_num}: {error_msg}", file=sys.stderr)
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
	conn = sqlite3.connect('/data/db/crawler.db')
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
crawl_abort_flags = {}  # Track which crawls should be aborted

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
	conn = sqlite3.connect('/data/db/crawler.db')
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

	# Rewrite img src attributes
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
	conn = sqlite3.connect('/data/db/crawler.db')
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

	def extract_links(self, html_content, base_url):
		"""
		Extract all resource links from HTML content for further crawling.

		Args:
			html_content (str): The HTML content to parse
			base_url (str): The base URL for resolving relative links

		Returns:
			list: List of unique URLs found in the HTML content
		"""
		soup = BeautifulSoup(html_content, 'html.parser')
		links = []

		# Extract regular page links (same host, same folder)
		for link in soup.find_all('a', href=True):
			href = link['href']
			absolute_url = urljoin(base_url, href).split('#')[0]
			if self.is_same_host_and_folder(absolute_url):
				links.append(absolute_url)

		# Extract CSS files (any host, any folder)
		for link in soup.find_all('link', rel='stylesheet', href=True):
			href = link['href']
			absolute_url = urljoin(base_url, href).split('#')[0]
			links.append(absolute_url)

		# Extract JavaScript files (any host, any folder)
		for script in soup.find_all('script', src=True):
			src = script['src']
			absolute_url = urljoin(base_url, src).split('#')[0]
			links.append(absolute_url)

		# Extract images (any host, any folder)
		for img in soup.find_all('img', src=True):
			src = img['src']
			absolute_url = urljoin(base_url, src).split('#')[0]
			links.append(absolute_url)
		for img in soup.find_all('img', srcset=True):
			candidates = [s.strip() for s in img['srcset'].split(',')]
			for candidate in candidates:
				parts = candidate.strip().split()
				if parts:
					srcset_url = parts[0]  # the URL part
					absolute_url = urljoin(base_url, srcset_url).split('#')[0]
					links.append(absolute_url)

		# Extract fonts from CSS @font-face rules (any host, any folder)
		font_urls = re.findall(r'url\(["\']?([^"\'()]+)["\']?\)', html_content)
		for font_url in font_urls:
			font_url = font_url.strip()
			if font_url and not font_url.startswith('data:'):  # Skip data URLs
				absolute_url = urljoin(base_url, font_url).split('#')[0]
				links.append(absolute_url)

		# Extract other resources (same host, any folder)
		for link in soup.find_all('link', href=True):
			rel = link.get('rel', [])
			if 'icon' in rel or 'shortcut' in rel:
				href = link['href']
				absolute_url = urljoin(base_url, href).split('#')[0]
				if self.is_same_host(absolute_url):
					links.append(absolute_url)

		return list(set(links))  # Remove duplicates

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
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.35 (KHTML, like Gecko) Chrome/116.1.0.9 Safari/537.35",
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.9"
			}

			response = requests.head(url, allow_redirects=True, headers=headers)
			content_length = response.headers.get('Content-Length')
			content_type = response.headers.get('content-type', 'text/html')
			status_code = response.status_code

			# Log the crawl attempt
			if self.logger:
				self.logger.log_url_crawl(url, status_code, content_type, content_length)

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

			# Get appropriate file extension
			if 'css' in content_type:
				ext = '.css'
			elif 'javascript' in content_type or 'ecmascript' in content_type:
				ext = '.js'
			elif 'image/' in content_type:
				ext = os.path.splitext(path)[1] or '.bin'
			elif 'font/' in content_type:
				ext = os.path.splitext(path)[1] or '.font'
			else:
				ext = os.path.splitext(path)[1] or '.html'

			# Create filename
			filename = f"{len(self.crawled_pages):04d}_{path.replace('/', '_')}{ext}"
			filepath = os.path.join(self.temp_dir, filename)

			if status_code == 200:
				# Get content
				response = requests.get(url, timeout=10, allow_redirects=True, headers=headers)

				# Save content (binary for non-text files)
				if 'text/' in content_type or 'application/javascript' in content_type or 'application/css' in content_type:
					with open(filepath, 'w', encoding='utf-8') as f:
						f.write(response.text)
				else:
					with open(filepath, 'wb') as f:
						f.write(response.content)

				# Extract links for further crawling
				if self.mode == 'simple':
					links = self.extract_links(response.text, url)

					# Also extract links from CSS files
					if 'css' in content_type:
						css_links = self.extract_css_links(response.text, url)
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

	def create_warc_archive(self):
		"""
		Create a WARC archive from all crawled pages.

		Returns:
			str: Path to the created WARC file
		"""
		warc_dir = "/data/archives"
		os.makedirs(warc_dir, exist_ok=True)

		# Extract hostname from start URL
		hostname = urlparse(self.start_url).netloc
		# Remove port if present
		if ':' in hostname:
			hostname = hostname.split(':')[0]

		warc_filename = f"temp_{hostname}.warc"
		warc_path = os.path.join(warc_dir, warc_filename)

		# Log WARC creation
		if self.logger:
			self.logger.log_warc_creation(warc_path, len(self.crawled_pages))
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

		return warc_path

	def crawl(self):
		"""
		Main crawling function that orchestrates the entire crawling process.

		This method handles the crawling loop, creates the WARC archive,
		and saves the results to the database.
		"""
		self.start_time = int(time.time())

        # Create temp directory
		self.temp_dir = "/data/temp/crawler_{}".format(threading.get_ident())
		os.makedirs(self.temp_dir, exist_ok=True)

		# Create log file path (will be alongside the WARC file)
		warc_dir = "/data/archives"
		os.makedirs(warc_dir, exist_ok=True)
		hostname = urlparse(self.start_url).netloc
		if ':' in hostname:
			hostname = hostname.split(':')[0]
		log_filename = f"temp_{hostname}.log"
		log_path = os.path.join(warc_dir, log_filename)

		# Initialize logger
		self.logger = CrawlLogger(log_path)
		self.logger.log_crawl_start(self.start_url, self.mode, self.max_size, self.niceness, self.restrictpage)

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
					# Clean up temp directory
					if self.temp_dir and os.path.exists(self.temp_dir):
						shutil.rmtree(self.temp_dir)
					return

				url = self.to_visit.pop(0)
				if url not in self.visited_urls:
					crawl_progress[url] = {
						'status': 'crawling',
						'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					}
					self.crawl_page(url)

					# Update stats
					crawl_stats[self.start_url]['total_completed'] = len(self.visited_urls)
					crawl_stats[self.start_url]['total_discovered'] = len(self.visited_urls) + len(self.to_visit)

					# Be respectful to the server (unless niceness is disabled)
					if self.niceness:
						time.sleep(0.5)

            # Create WARC archive
			self.warc_file = self.create_warc_archive()

			# Check if any page were archived
			status = 'completed'
			if len(self.crawled_pages) == 0:
				status = 'error: no page crawled.'

			# Save to database
			conn = sqlite3.connect('/data/db/crawler.db')
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
			new_filename = f"{archive_id:03d}_{hostname}.warc"
			new_path = os.path.join(os.path.dirname(self.warc_file), new_filename)
			os.rename(self.warc_file, new_path)
			self.warc_file = new_path
			
			# Also rename the log file
			if hasattr(self, 'logger') and self.logger:
				log_filename = f"{archive_id:03d}_{hostname}.log"
				log_new_path = os.path.join(os.path.dirname(self.logger.log_file_path), log_filename)
				os.rename(self.logger.log_file_path, log_new_path)
				self.logger.log_file_path = log_new_path

			# Update database with new filename
			conn = sqlite3.connect('/data/db/crawler.db')
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

			# Clean up temp directory
			shutil.rmtree(self.temp_dir)

		except Exception as e:
			# Update status to error
			traceback.print_exception(type(e), e, e.__traceback__, file=sys.stderr)
			print("[ERROR] Crawl thread failed. Cleaning up.", file=sys.stderr)
			
			# Log the error if logger is available
			if hasattr(self, 'logger') and self.logger:
				self.logger.log_crawl_error(str(e))
			conn = sqlite3.connect('/data/db/crawler.db')
			cursor = conn.cursor()
			log_file_path = self.logger.log_file_path if hasattr(self, 'logger') and self.logger else ''
			cursor.execute('''
				INSERT INTO archives (url, mode, warc_file, log_file, pages_crawled, status, crawl_time, max_size)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			''', (self.start_url, self.mode, '', log_file_path, 0, f'error: {str(e)}', (int(time.time()) - self.start_time), self.max_size))
			conn.commit()
			conn.close()

			if self.temp_dir and os.path.exists(self.temp_dir):
				shutil.rmtree(self.temp_dir)

@app.route('/')
def index():
	"""
	Main page route that displays the crawler interface and list of archives.

	Returns:
		Rendered HTML template with archives data
	"""
	try:
		conn = sqlite3.connect('/data/db/crawler.db')
		cursor = conn.cursor()
		cursor.execute('SELECT * FROM archives ORDER BY created_at DESC')
		archives = cursor.fetchall()
		conn.close()
		
		return render_template('crawler.html', archives=archives)
	except Exception as e:
		print(f"Error in index route: {e}")
		import traceback
		traceback.print_exc()
		return f"Error loading archives: {str(e)}", 500

@app.route('/version')
def get_version():
	"""
	Get application version information.

	Returns:
		JSON response with version details
	"""
	return jsonify({
		'version': __version__,
		'name': 'Web Crawler',
		'description': 'This is a modern self-hosted web crawler application that creates WARC archives from web sites.'
	})


@app.route('/start_crawl', methods=['POST'])
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
	if mode not in ['simple', 'advanced']:
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

	# Start crawling in a separate thread
	crawler = WebCrawler(sanitized_url, mode, max_size, niceness, restrictpage)
	thread = threading.Thread(target=crawler.crawl)
	thread.daemon = True
	thread.start()

	return jsonify({'message': 'Crawl started', 'url': sanitized_url, 'mode': mode, 'max_size': max_size, 'niceness': niceness, 'restrictpage': restrictpage})

@app.route('/progress')
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

@app.route('/abort_crawl', methods=['POST'])
def abort_crawl():
	"""
	Abort an ongoing crawl process.

	Returns:
		JSON response with abort status or error message
	"""
	url = request.form.get('url')
	if not url:
		return jsonify({'error': 'URL is required'}), 400

	# Set abort flag for this URL
	crawl_abort_flags[url] = True

	# Update crawl stats to show aborted status
	if url in crawl_stats:
		crawl_stats[url]['status'] = 'aborted'

	return jsonify({'message': 'Crawl abort requested', 'url': url})

@app.route('/delete/<int:archive_id>', methods=['POST'])
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
	conn = sqlite3.connect('/data/db/crawler.db')
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
		conn = sqlite3.connect('/data/db/crawler.db')
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
	conn = sqlite3.connect('/data/db/crawler.db')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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
					if content_type.startswith('text/') or content_type.startswith('application/javascript') or content_type.startswith('application/css'):
						# Text content - decode as UTF-8
						content = content_bytes.decode('utf-8', errors='ignore')

						# For HTML and CSS content, rewrite URLs to point to archived files
						if content_type.startswith('text/html'):
							content = rewrite_html_urls(content, sanitized_id, url)
						elif content_type.startswith('text/css'):
							content = rewrite_css_urls(content, sanitized_id, url)
					else:
						# Binary content (images, etc.) - encode as base64
						content = base64.b64encode(content_bytes).decode('utf-8')

					return render_template('file_viewer.html',
						content=content,
						content_type=content_type,
						url=url,
						status_code=status_code,
						archive_id=sanitized_id)

		return "Record not found", 404
	except Exception as e:
		return f"Error reading WARC file: {str(e)}", 500

@app.route('/raw_file/<int:archive_id>/<int:record_index>')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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
def get_ignore_patterns():
	"""
	Get all ignore patterns for URL exclusion.

	Returns:
		JSON response with list of ignore patterns
	"""
	conn = sqlite3.connect('/data/db/crawler.db')
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
	conn = sqlite3.connect('/data/db/crawler.db')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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

	conn = sqlite3.connect('/data/db/crawler.db')
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

def ensure_directories():
	"""
	Ensure all required directories exist.
	"""
	directories = [
		'/data',
		'/data/db',
		'/data/temp',
		'/data/archives'
	]
	
	for directory in directories:
		os.makedirs(directory, exist_ok=True)
		print(f"Ensured directory exists: {directory}")

if __name__ == '__main__':
	# Ensure directories exist
	ensure_directories()
	
	# Initialize database
	init_db()
	
	# Get SSL context if certificates exist
	ssl_context = None
	cert_path = os.environ.get('SSL_CERT_PATH', '/etc/certs/wildcard.dendory.net.crt')
	key_path = os.environ.get('SSL_KEY_PATH', '/etc/certs/wildcard.dendory.net.key')
	
	if os.path.exists(cert_path) and os.path.exists(key_path):
		ssl_context = (cert_path, key_path)
		print(f"SSL enabled with certificates: {cert_path}, {key_path}")
	else:
		print("SSL disabled - certificates not found")
	
	# Get host and port from environment
	host = os.environ.get('FLASK_HOST', '0.0.0.0')
	port = int(os.environ.get('FLASK_PORT', 8080))
	
	print(f"Starting Web Crawler v{__version__} on {host}:{port}")
	
	# Run the application
	app.run(host=host, port=port, ssl_context=ssl_context, threaded=True)
