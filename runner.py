#!/usr/bin/python3
# This script collects externally downloaded WARC archives

from warcio.archiveiterator import ArchiveIterator
from pathlib import Path
import datetime
import sqlite3
import subprocess
import logging
import json
import os

dbname = "/data/db/crawler.db"
crawlsdir = "/data/archives"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger("crawler_mapper")

# Ensure directories exist
os.makedirs(os.path.dirname(dbname), exist_ok=True)
os.makedirs(crawlsdir, exist_ok=True)

db = sqlite3.connect(dbname)
cur = db.cursor()

# Check for deleted files
cur = db.cursor()
files = cur.execute("SELECT warc_file FROM archives;").fetchall()
for file in files:
	fd = Path(file[0])
	if not fd.is_file(): # File doesn't exist anymore
		print("* Removing: {}".format(file))
		cur.execute("DELETE FROM archives WHERE warc_file = ?;", [file[0]])
db.commit()

# Check for new files
try:
    result = subprocess.run(["find", crawlsdir, "-type", "f"], capture_output=True, text=True, check=True)
    files = result.stdout.strip().split('\n')
except subprocess.CalledProcessError:
    files = []

for file in files: # Iterate files in folder
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
					cur.execute("INSERT INTO archives (url, mode, warc_file, pages_crawled, status, crawl_time, max_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", (base_url, "manual", file, record_count, "completed", 0, 0, created_on))
					db.commit()
				except:
					log.warning("Failed to parse {}".format(file))

db.close()
