#!/usr/bin/python

import os
import sys
import csv
import time
import zlib
import glob
import socket
import base64
import zipfile
import urllib2
import datetime

# PATHS
OUTPUT_DIR              = "output"
DATA_DIR                = "testData"
TEMP_DIR                = "tempDir"
MALWARES_URL_FILE       = DATA_DIR + "/" + "malwareURLs.csv"
NETWORK_LOGPAGE         = OUTPUT_DIR + "/" + "network.log"
NETWORK_VERBOSE_LOGPAGE = OUTPUT_DIR + "/" + "network_verbose.log"
EICAR_FILE_TEST         = OUTPUT_DIR + "/" + "eicar.log"
MALWARE_REPORT_FILE     = OUTPUT_DIR + "/" + "malware.log"

# Malwares
MALWARES = [
    { "name": "Android Spy 49 iBanking", "path": "Android.Spy.49_iBanking_Feb2014"},
    { "name": "Artemis", "path": "Artemis"},
    { "name": "BlackEnergy 2.1", "path": "BlackEnergy2.1"},
    { "name": "CryptoLocker 2014", "path": "CryptoLocker_22Jan2014"},
    { "name": "Duqu2", "path": "Duqu2"},
    { "name": "Linux.Wirenet", "path": "Linux.Wirenet"},
    { "name": "OSX_Wirenet", "path": "OSX_Wirenet"},
    { "name": "CryptoWall", "path": "CryptoWall"},
    { "name": "Ransomware.Locky", "path": "Ransomware.Locky"},
    { "name": "Skywiper-A.Flame", "path": "Skywiper-A.Flame"},
    { "name": "Trojan.Loadmoney", "path": "Trojan.Loadmoney"},
    { "name": "Win32.Infostealer.Dexter", "path": "Win32.Infostealer.Dexter"},
    { "name": "ZeusGameover_Feb2014", "path": "ZeusGameover_Feb2014"},
]


# URLS
EICAR_URL       = "http://www.eicar.org/download/eicar.com"
complete_db     =  "http://www.malwaredomainlist.com/mdlcsv.php" # Complete DB
yesterday_db    = "http://www.malwaredomainlist.com/hostslist/yesterday.php" # Yesterday's DB
yesterday_urls  = "http://www.malwaredomainlist.com/hostslist/yesterday_urls.php" # Only URLs from yesterday
live_ips        = "http://www.malwaredomainlist.com/hostslist/ip.txt" # Online LIVE IP list

# Configurations
SCAN_TIMEOUT = 5 # 5 seconds until AV should pick it up
socket.setdefaulttimeout(SCAN_TIMEOUT)


# START ASSISTING FUNCTIONS
def _percentage(per, sum_):
    return 100 * float(per)/float(sum_)

def _flash_logfiles():
    f = open(NETWORK_VERBOSE_LOGPAGE, 'w')
    f.close()
    f = open(NETWORK_LOGPAGE, 'w')
    f.close()
    f = open(EICAR_FILE_TEST, 'w')
    f.close()
    f = open(MALWARE_REPORT_FILE, 'w')
    f.close()

def _fetchURL(url):
    try:
        response = urllib2.urlopen(url)
        html = response.read()
        return html
    except:
        return False

def _dns_resolve(param):
    try:
        data = socket.gethostbyname_ex(param)
        return data[2][0]
    except:
        return False

def _connect_port(host, port=80):
    try:
        sock = socket.socket()
        sock.connect((host, port))
        sock.close()
        return True
    except:
        return False

def _getMalwareList(filename=MALWARES_URL_FILE, count=20):
    retMe = []
    with open(MALWARES_URL_FILE) as csvfile:
        reader = csv.reader(csvfile)
        i = 0
        for row in reader:
            if i == count:
                break
            date = row[0]
            url = row[1]
            desc = row[4]
            if date == "-" or url == "-" or desc == "-":
                continue
            if not "/" in url:
                continue
            domain = url.split('/')[0]
            exists = False
            for j in retMe:
                if j['domain'] == domain:
                    exists = True
            if exists:
                continue
            else:
                retMe.append({'date': date, 'url': "http://"+url, 'domain': domain, 'desc': desc})
                i += 1
        return retMe

def _createZip(folder=OUTPUT_DIR):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    zf = zipfile.ZipFile("Report-%s.zip" % now, "w")
    for dirname, subdirs, files in os.walk(folder):
        zf.write(dirname)
        for filename in files:
            zf.write(os.path.join(dirname, filename))
    zf.close()
    return "Report-%s.zip" % now

# END ASSISTING FUNCTIONS


# START MAIN FUNCTIONS


def logit(kind, title, desc, result):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if kind == "network-verbose":
        f = open(NETWORK_LOGPAGE, 'a')
        f.write(now + ", " + title + ", " + desc + ", " + result + "\n")
        f.close()
    elif kind == "network":
        f = open(NETWORK_VERBOSE_LOGPAGE, 'a')
        f.write(now + ", " + title + ", " + desc + ", " + result + "\n")
        f.close()
    elif kind == "eicar":
        f = open(EICAR_FILE_TEST, 'a')
        f.write(now + ", " + title + ", " + desc + ", " + result + "\n")
        f.close()
    elif kind == "malware":
        f = open(MALWARE_REPORT_FILE, 'a')
        f.write(now + ", " + title + ", " + desc + ", " + result + "\n")
        f.close()
    return True


def NetworkTest():
    sys.stdout.write("Starting Malware Traffic Test.\n")
    malwareIndex = _getMalwareList(count=30)
    counter = 0
    detection_counter = 0
    circumvented_counter = 0

    # Setup Progress Bar
    toolbar_width = len(malwareIndex)

    try:
        for malwareURL in malwareIndex:
            # DNS Resolution Test
            req = _dns_resolve(malwareURL['domain'])
            if req is False:
                logit(kind="network", title=malwareURL['domain'], desc="DNS", result="False")
                logit(kind="network-verbose", title=malwareURL['domain'], desc="DNS", result="False")
                counter += 1
                detection_counter += 1
                continue
            else:
                logit(kind="network", title=malwareURL['domain'], desc="DNS", result=req)

            # Port Test
            port_state = _connect_port(host=malwareURL['domain'], port=80)
            if port_state is False:
                logit(kind="network", title=malwareURL['domain'], desc="Port", result="False")
                logit(kind="network-verbose", title=malwareURL['domain'], desc="Port", result="False")
                counter += 1
                detection_counter += 1
                continue
            else:
                logit(kind="network", title=malwareURL['domain'], desc="Port", result="Open")

            # Get URL
            html = _fetchURL(url=malwareURL['url'])
            if html is False:
                logit(kind="network", title=malwareURL['domain'], desc="GET", result="False")
                logit(kind="network-verbose", title=malwareURL['domain'], desc="GET", result="False")
                counter += 1
                detection_counter += 1
                sys.stdout.write("-")
                sys.stdout.flush()
                continue
            else:
                logit(kind="network", title=malwareURL['domain'], desc="GET", result=str(len(html)))
                logit(kind="network-verbose", title=malwareURL['domain'], desc="GET", result=str(len(html)))
                counter += 1
                circumvented_counter += 1
    except:
        sys.stdout.write("\nKEYBOARD INTERRUPT!\n")
        sys.exit()

    sys.stdout.write("Completed Malware Traffic Test.\n\n")
    return [len(malwareIndex), detection_counter, circumvented_counter]


def EicarTest():
    sys.stdout.write("Starting EICAR test.\n")
    eicarData = _fetchURL(url=EICAR_URL)
    if eicarData is False:
        sys.stderr.write("No internet connection to get EICAR file.\n")
        return [0,0,0]
    detection = 0
    evasion = 0

    # Base64 Test
    eicarb64 = base64.b64encode(eicarData)
    f = open("%s/b64.log" % TEMP_DIR, "wb")
    f.write(eicarb64)
    f.close()
    time.sleep(SCAN_TIMEOUT)
    exists = os.path.exists("%s/b64.log" % TEMP_DIR)
    if exists:
        logit(kind="eicar", title="EICAR", desc="Base64", result="Exists")
        evasion += 1
    else:
        logit(kind="eicar", title="EICAR", desc="Base64", result="Detection")
        detection += 1

    # Plain Text Test
    f = open("%s/plain.log" % TEMP_DIR, "wb")
    f.write(eicarData)
    f.close()
    time.sleep(SCAN_TIMEOUT)
    exists = os.path.exists("%s/plain.log" % TEMP_DIR)
    if exists:
        logit(kind="eicar", title="EICAR", desc="Plain", result="Exists")
        evasion += 1
    else:
        logit(kind="eicar", title="EICAR", desc="Plain", result="Detection")
        detection += 1

    # PNG Test
    png = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x37\x6e\xf9\x24\x00\x00\x00\x10\x49\x44\x41\x54\x78\x9c\x62\x60\x01\x00\x00\x00\xff\xff\x03\x00\x00\x06\x00\x05\x57\xbf\xab\xd4\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"
    f = open("%s/small.png" % TEMP_DIR, "wb")
    f.write(png+eicarData)
    f.close()
    time.sleep(SCAN_TIMEOUT)
    exists = os.path.exists("%s/small.png" % TEMP_DIR)
    if exists:
        logit(kind="eicar", title="EICAR", desc="PNG", result="Exists")
        evasion += 1
    else:
        logit(kind="eicar", title="EICAR", desc="PNG", result="Detection")
        detection += 1

    # ZIP Test
    f = open("%s/zippy.zip" % TEMP_DIR, "wb")
    f.write(zlib.compress(eicarData))
    f.close()
    time.sleep(SCAN_TIMEOUT)
    exists = os.path.exists("%s/zippy.zip" % TEMP_DIR)
    if exists:
        logit(kind="eicar", title="EICAR", desc="Zip", result="Exists")
        evasion += 1
    else:
        logit(kind="eicar", title="EICAR", desc="Zip", result="Detection")
        detection += 1

    # ZIP Large Test
    f = open("%s/big_ei.zip" % TEMP_DIR, "wb")
    f.seek(3373256576-1)
    f.write(eicarData)
    f.close()
    time.sleep(SCAN_TIMEOUT)
    exists = os.path.exists("%s/big_ei.zip" % TEMP_DIR)
    if exists:
        logit(kind="eicar", title="EICAR", desc="Zip-Large", result="Exists")
        evasion += 1
    else:
        logit(kind="eicar", title="EICAR", desc="Zip-Large", result="Detection")
        detection += 1

    # Clean Files
    for fl in glob.glob(TEMP_DIR+"/*"):
        os.remove(fl)
    sys.stdout.write("Completed EICAR testing.\n\n")
    return [5, evasion, detection]


def MalwareDeploymentTest():
    sys.stdout.write("Starting malware test.\n")
    malware_counter = len(MALWARES)
    detection = 0
    evasion = 0

    for malware in MALWARES:
        try:
            filePath = "%s/%s.zip" % (DATA_DIR, malware['path'])
            zipHandler = zipfile.ZipFile(filePath, 'r')
            zipHandler.extractall(TEMP_DIR, pwd='infected')
            zipHandler.close()
        except IOError, e:
            sys.stderr.write("Error locating file %s.\n" % filePath)
            continue

        time.sleep(SCAN_TIMEOUT)
        exists = os.path.exists("%s/%s.bin" % (TEMP_DIR, malware['path']))
        if exists:
            logit(kind="malware", title="Malware Dropped", desc=malware['name'], result="Evasion")
            evasion += 1
        else:
            logit(kind="malware", title="Malware Dropped", desc=malware['name'], result="Detection")
            detection += 1

        os.remove("%s/%s.bin" % (TEMP_DIR, malware['path']))

    # Verify Clean Files
    for fl in glob.glob(TEMP_DIR+"/*"):
        os.remove(fl)
    sys.stdout.write("Completed malware testing.\n\n")
    return [malware_counter, evasion, detection]

# END MAIN FUNCTIONS


if __name__ == "__main__":
    _flash_logfiles()
    net = NetworkTest()
    eicar = EicarTest()
    malware = MalwareDeploymentTest()
    archive_name = _createZip()

    sys.stdout.write("\n\n")
    sys.stdout.write("--- Summary ---\n")
    sys.stdout.write("\tNetwork Detection and Mitigations\n")
    sys.stdout.write("\t\t%s/%s were blocked. That is a %s%% detection rate.\n\n" % (net[2], net[0], _percentage(net[2], net[0])))
    sys.stdout.write("\tEICAR Test File\n")
    sys.stdout.write("\t\t%s/%s were blocked. That is a %s%% detection rate.\n\n" % (eicar[2], eicar[0], _percentage(eicar[2], eicar[0])))
    sys.stdout.write("\tMalware Dropping Test\n")
    sys.stdout.write("\t\t%s/%s were blocked. That is a %s%% detection rate.\n" % (malware[2], malware[0], _percentage(malware[2], malware[0])))
    sys.stdout.write("\tReport archive was created at '%s'.\n" % archive_name)
    sys.stdout.write("--- End of Report ---\n")
    sys.stdout.write("\n\n")
