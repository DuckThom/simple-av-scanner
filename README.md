# simple-av-scanner
Simple AV scanner (wrapper for ClamAV)

## Requirements

- Clam AV
- Python3
- Python module: clamd

## Setup

1. In `/etc/clamav/clamd.conf` uncomment/edit the following line: `LocalSocket /run/clamav/clamd.ctl`
2. Run `sudo systemctl enable --now clamav-daemon` (or your system equivalent)
3. Run `python3 av-scanner.py`

## Usage

### Options

- `DISABLE_LOGGING` > Disable the log messages (Default: Logging enabled)
- `SCAN_DIR` > Absolute path of the directory you wish to scan (Default: $HOME)
- `QUARANTINE_DIR` > Directory where quarantined items should be moved to. (**Note** Must be writable for the current user) (Default: /var/lib/clamav/quarantine)
- `DB_FILE` > The location of the database file which keeps track of the scanner/changed files. (Default: /var/lib/av-scanner/file-cache.db)

### Syntax

```
DISABLE_LOGGING=1 SCAN_DIR=/var/www/uploads QUARANTINE_DIR=/var/av/quarantine DB_FILE=/var/run/av.db python3 av-scanner.py
```
