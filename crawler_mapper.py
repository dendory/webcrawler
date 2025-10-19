#!/usr/bin/python3
# This script collects externally downloaded WARC archives

from warcio.archiveiterator import ArchiveIterator
from pathlib import Path
import datetime
import sqlite3
import json
import sys
import os
import configparser
import subprocess
import logging

def load_config(config_file=None):
	"""
	Load configuration from crawler.cfg file.

	Args:
		config_file (str, optional): Path to config file. If None, uses default location.

	Returns:
		configparser.ConfigParser: Loaded configuration object
	"""
	config = configparser.ConfigParser()
	
	# Use provided config file or default location
	if config_file is None:
		config_file = os.path.join(os.path.dirname(__file__), 'crawler.cfg')

	if os.path.exists(config_file):
		config.read(config_file)
		# Strip quotes from all values
		for section in config.sections():
			for key in config[section]:
				value = config[section][key]
				if isinstance(value, str) and value.startswith('"') and value.endswith('"'):
					config[section][key] = value[1:-1]
	else:
		print(f"Configuration file {config_file} could not be loaded.", file=sys.stderr)
		quit(1)

	return config

if __name__ == '__main__':
	# Parse command line arguments
	import argparse
	parser = argparse.ArgumentParser(description='Web Crawler Mapper')
	parser.add_argument('--config', '-c', help='Path to configuration file', 
	                   default='/opt/crawler/config/crawler.cfg')
	args = parser.parse_args()
	
	# Load configuration
	cfg = load_config(args.config)
	dbname = cfg.get('general', 'db_file')
	crawlsdir = cfg.get('general', 'archives_dir')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger("crawler_mapper")
db = sqlite3.connect(dbname)
cur = db.cursor()

# Check for deleted files (only if enabled in config)
process_deleted_files = cfg.getboolean('runner', 'process_deleted_files', fallback=False)
if process_deleted_files:
	cur = db.cursor()
	files = cur.execute("SELECT warc_file FROM archives;").fetchall()
	for file in files:
		fd = Path(file[0])
		if not fd.is_file(): # File doesn't exist anymore
			print("* Removing: {}".format(file))
			cur.execute("DELETE FROM archives WHERE warc_file = ?;", [file[0]])
	db.commit()
else:
	print("* Skipping deleted file processing (disabled in config)")

# Check for new files (only if enabled in config)
process_new_files = cfg.getboolean('runner', 'process_new_files', fallback=True)
if process_new_files:
	try:
		result = subprocess.run(["find", crawlsdir, "-type", "f"], capture_output=True, text=True, check=True)
		files = result.stdout
	except subprocess.CalledProcessError as e:
		log.error(f"Error finding files in {crawlsdir}: {e}")
		files = ""
	
	for file in files.split('\n'): # Iterate files in folder
		if file != crawlsdir:
			if ".warc" in file or ".WARC" in file:
				rows = cur.execute("SELECT COUNT(*) FROM archives WHERE warc_file = ?;", [file]).fetchall()
				if rows[0][0] == 0: # File isn't already in the database
					try:
						record_count = 0
						base_url = ""
						with open(file, 'rb') as stream:
							for record in ArchiveIterator(stream):
								record_count += 1
								if record.rec_type == 'response' and base_url == "":
									base_url = record.rec_headers.get_header('WARC-Target-URI')
						stat = os.stat(file)
						timestamp = getattr(stat, 'st_birthdate', stat.st_ctime)
						created_on = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
						print("* Adding: {}".format(file))
						cur = db.cursor()
						cur.execute("INSERT INTO archives (url, mode, warc_file, log_file, pages_crawled, status, crawl_time, max_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", (base_url, "manual", file, None, record_count, "completed", 0, 0, created_on))
						db.commit()
					except Exception as e:
						log.warning(f"Failed to parse {file}: {e}")
else:
	print("* Skipping new file processing (disabled in config)")

db.close()
