# Web Crawler

This is a modern self-hosted web crawler application that creates WARC archives from web sites with a WARC viewer.

## Features

- **Web-based Interface**: Easy-to-use web interface for starting and managing crawls
- **WARC Archive Creation**: Creates standard WARC (Web ARChive) files for long-term preservation
- **Comprehensive Logging**: Detailed logging of all crawl activities with timestamps
- **URL Filtering**: Configurable ignore patterns to exclude unwanted URLs
- **Internet Archive Upload**: Direct upload capability to Internet Archive
- **Real-time Progress**: Live progress tracking during crawl operations
- **Crawl Abortion**: Ability to abort ongoing crawls
- **Archive Management**: View, download, and delete archived content

## Quick Start

### Using Docker (Recommended)

1. **Pull the image:**
   ```bash
   docker pull webcrawler:latest
   ```

2. **Run the container:**
   ```bash
   docker run -d \
     --name webcrawler \
     -p 8080:8080 \
     -v /path/to/your/data:/data \
     webcrawler:latest
   ```

3. **Access the web interface:**
   Open your browser and navigate to `http://localhost:8080`

### Manual Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Create data directories:**
   ```bash
   mkdir -p /data/{db,temp,archives}
   ```

3. **Run the application:**
   ```bash
   python crawler.py
   ```

## Directory Structure

```
/app/                    # Application code
├── crawler.py          # Main application
├── runner.py           # Scheduled maintenance script
├── templates/          # HTML templates
├── requirements.txt    # Python dependencies
└── README.md          # This file

/data/                  # Data directory (mounted as volume)
├── db/                # SQLite database
├── temp/              # Temporary crawl files
└── archives/          # WARC and log files
```

## Configuration

### Environment Variables

- `FLASK_HOST`: Host to bind to (default: 0.0.0.0)
- `FLASK_PORT`: Port to bind to (default: 8080)
- `SSL_CERT_PATH`: Path to SSL certificate (optional)
- `SSL_KEY_PATH`: Path to SSL private key (optional)

### Data Persistence

The `/data` directory should be mounted as a volume to persist:
- Database files
- WARC archives
- Log files
- Temporary crawl data

## Usage

### Starting a Crawl

1. Open the web interface
2. Enter the URL to crawl
3. Configure crawl options:
   - **Crawl Mode**: Simple (wget style) or Advanced (chrome headless browser)
   - **Max Size**: Maximum file size to download (in bytes)
   - **Be Nice**: Add delays between requests (0.5 secs)
   - **Limit to Same Page**: Restrict crawling to same web page or sub-pages, otherwise the folder is used
4. Click "Start" to begin crawling

### Managing Archives

- **View Archive**: Browse archived content in a web interface
- **Log Details**: View detailed crawl logs with timestamps
- **Upload to IA**: Upload archives to Internet Archive
- **Delete**: Remove archives and associated files

### URL Filtering

Configure ignore patterns to exclude unwanted URLs:
- Use regex patterns for flexible matching
- Enable/disable patterns as needed
- Built-in patterns for common exclusions

## API Endpoints

### Crawl Management
- `POST /start_crawl` - Start a new crawl
- `POST /abort_crawl` - Abort an ongoing crawl
- `GET /progress` - Get crawl progress

### Archive Management
- `GET /view_archive/<id>` - View archive contents
- `GET /log_file/<id>` - Get crawl log file
- `POST /delete/<id>` - Delete an archive
- `POST /ia/<id>` - Upload to Internet Archive

### File Access
- `GET /view_file/<archive_id>/<record_index>` - View archived file
- `GET /raw_file/<archive_id>/<record_index>` - Get raw file content

## Logging

The application creates detailed logs for each crawl:
- Timestamped entries for all activities
- URL crawling status and HTTP response codes
- Error messages and warnings
- Link discovery and filtering information
- WARC file creation details

Log files are saved alongside WARC files with `.log` extension.

## Maintenance

The `runner.py` script runs automatically every 5 minutes to:
- Clean up manually deleted WARC files from the database
- Import new WARC files found in the archives directory

## Version History

- **0.1.0** - Initial release with basic crawling functionality
- **0.1.1** - Added comprehensive logging system
- **0.1.2** - Added crawl abortion and improved UI

## License

Copyright © 2025 Patrick Lambert [patrick@dendory.ca]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

