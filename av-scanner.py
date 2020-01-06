import sqlite3
import os
import clamd
import shutil
import progressbar
from subprocess import check_output

# Set the absolute path that should be scanned
PATH_TO_SCAN = os.environ['SCAN_DIR'] if 'SCAN_DIR' in os.environ else os.environ['HOME']

# Set the path of the quarantine dir
QUARANTINE_DIR = os.environ['QUARANTINE_DIR'] if 'QUARANTINE_DIR' in os.environ else '/var/lib/clamav/quarantine'

# Set the path to the sqlite db file
DB_FILE_PATH = os.environ['DB_FILE'] if 'DB_FILE' in os.environ else '/var/lib/av-scanner/file-cache.db'

# ClamAV daemon socket path
CLAMS_SOCKET_PATH = os.environ['SOCKET_PATH'] if 'SOCKET_PATH' in os.environ else '/run/clamav/clamd.ctl'

# ---------

def log_line(text):
    print(text)

if os.access(PATH_TO_SCAN, os.R_OK) == False:
    log_line("Error: Scan path " + PATH_TO_SCAN + " is not readable")
    exit(1)

if os.access(QUARANTINE_DIR, os.W_OK) == False:
    log_line("Error: Quarantine directory " + QUARANTINE_DIR + " is not writable")
    exit(1)

if os.access(DB_FILE_PATH, os.W_OK) == False:
    log_line("Error: SQLite DB file " + DB_FILE_PATH + " is not accessible, does the file exist?")
    exit(1)

if os.access(CLAMS_SOCKET_PATH, os.W_OK) == False:
    log_line("Error: ClamAV Daemon socket file  " + CLAMS_SOCKET_PATH + " is not accessible, is the clamav-daemon service running?")
    exit(1)

scannedFileCount = 0

db = sqlite3.connect(DB_FILE_PATH)
db.row_factory = sqlite3.Row

theClams = clamd.ClamdUnixSocket(path=CLAMS_SOCKET_PATH)

def get_file_list():
    log_line("Building file list")
    
    files = []

    for r, d, f in os.walk(PATH_TO_SCAN.encode('utf8', 'surrogateescape')):
        for file in f:
            filePath = os.path.join(r, file)

            if os.access(filePath, os.R_OK) == False or os.path.isfile(filePath) == False:
                continue

            files.append(filePath)

    return files

def create_database():
    c = db.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS files (hash text, size text, path text)')
    db.commit()

def close_database():
    db.close()

def scan_files():
    global scannedFileCount

    log_line("Starting file scanner")

    c = db.cursor()
    files = get_file_list()

    for filePath in progressbar.progressbar(files, redirect_stdout=True):
        # Check if the file to be scanned still exists,
        # it could be removed if it was a cache file
        if os.access(filePath, os.R_OK) == False or os.path.isfile(filePath) == False:
            continue

        fileHash = check_output([ "sha1sum", filePath ]).split()[0]
        fileSize = str(os.path.getsize(filePath))

        c.execute('SELECT * FROM files WHERE path = ?', [ filePath ])
        DB_FILE_PATH = c.fetchone()

        if DB_FILE_PATH is None:
            scan(filePath)
            c.execute('INSERT INTO files VALUES (?,?,?)', [ fileHash, fileSize, filePath ])

        elif DB_FILE_PATH['size'] != fileSize or DB_FILE_PATH['hash'] != fileHash:
            scan(filePath)
            c.execute('UPDATE files SET hash = ?, size = ? WHERE path = ?', [ fileHash, fileSize, filePath ])

        if (scannedFileCount % 10) == 0 and scannedFileCount != 0:
            db.commit()

def scan(f):
    global scannedFileCount

    f = f.decode('utf8', 'surrogateescape')

    log_line("Scanning " + f)

    scannedFileCount += 1
    res = theClams.scan(f).get(f, None)

    if res is None:
        log_line("Scan result empty, is the file readable?" + f)
        return

    if res[0] == 'FOUND':
        logger.warning("POSSIBLE VIRUS FOUND IN " + f)
        shutil.move(f, QUARANTINE_DIR)

# Run the program

create_database()
scan_files()
close_database()
