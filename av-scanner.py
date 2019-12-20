import sqlite3
import os
import clamd
import shutil
from subprocess import check_output

# Set the absolute path that should be scanned
pathToScan = os.environ['SCAN_DIR'] if 'SCAN_DIR' in os.environ else os.environ['HOME']

# Set the path of the quarantine dir
quarantineDir = os.environ['QUARANTINE_DIR'] if 'QUARANTINE_DIR' in os.environ else '/var/lib/clamav/quarantine'

# Set the path to the sqlite db file
dbFile = os.environ['DB_FILE'] if 'DB_FILE' in os.environ else '/var/lib/av-scanner/file-cache.db'

# Enable or disable logging
logging = False if 'DISABLE_LOGGING' in os.environ else True

# ---------

def logLine(line):
    print(line) if logging else None

if os.access(pathToScan, os.R_OK) == False:
    logLine("Error: Scan path " + pathToScan + " is not readable");
    exit(1)

if os.access(quarantineDir, os.W_OK) == False:
    logLine("Error: Quarantine directory " + quarantineDir + " is not writable");
    exit(1)

scannedFileCount = 0

logLine("Opening database")
db = sqlite3.connect(dbFile)
db.row_factory = sqlite3.Row

logLine("Connecting to ClamAV Daemon")
theClams = clamd.ClamdUnixSocket(path="/run/clamav/clamd.ctl")

def create_database():
    c = db.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS files (hash text, size text, path text)')
    db.commit()

def close_database():
    logLine("Closing database")
    db.close()

def scan_files():
    global scannedFileCount

    logLine("Starting file scanner")

    c = db.cursor()

    for r, d, f in os.walk(pathToScan):
        for file in f:
            filePath = os.path.join(r, file)

            if os.access(filePath, os.R_OK) == False or os.path.isfile(filePath) == False:
                logLine("Skipping " + filePath + " File not readable or is a special file")
                continue

            fileHash = check_output([ "sha1sum", filePath ]).split()[0]
            fileSize = str(os.path.getsize(filePath))

            c.execute('SELECT * FROM files WHERE path = ?', [ filePath ])
            dbFile = c.fetchone()

            if dbFile is None:
                scan(filePath)
                c.execute('INSERT INTO files VALUES (?,?,?)', [ fileHash, fileSize, filePath ])

            elif dbFile['size'] != fileSize or dbFile['hash'] != fileHash:
                scan(filePath)
                c.execute('UPDATE files SET hash = ?, size = ? WHERE path = ?', [ fileHash, fileSize, filePath ])

            if (scannedFileCount % 10) == 0 and scannedFileCount != 0:
                logLine('Saving DB')
                db.commit()


def scan(f):
    global scannedFileCount

    logLine("Scanning " + f)

    scannedFileCount += 1
    res = theClams.scan(f).get(f, None)

    if res is None:
        logLine("Scan result empty, is the file readable?" + f)
        return

    if res[0] == 'FOUND':
        logLine("POSSIBLE VIRUS FOUND IN " + f)
        shutil.move(f, quarantineDir)

# Run the program

create_database()
scan_files()
close_database()
