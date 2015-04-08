#!/usr/bin/python

# http://www.dnspython.org/ We require >= 1.9 (because of DNSSEC)
import dns.resolver, dns.message, dns.query, dns.dnssec, dns.rdtypes
import sqlite3
import sys
import re
import time
import base64
import hashlib
import smtplib
import ConfigParser
import os
import random
import logging
import logging.handlers
from email.Utils import formatdate

# Default values, some may be overriden by the configuration file
edns_size = 4096
max_tests = 5
mytimeout = 3
mail_server = "localhost"
database_name = "dnssec.sqlite"
email_prefix = "DNSSEC check"
maintainer_address = "foo@bar"
output = True
syslog = False
SECTION = "default"
version = sys.argv[0] + " $Revision: 10774 $ (Python %s)" % \
          re.sub ("\n", " ", sys.version)
# A sample configuration file:
# [default]
# mailserver: smtp.free.fr
# database: test.sqlite
# prefix: DNSSEC Check at AFNIC
# maintainer: Stephane.Bortzmeyer+dnssec-key-check@nic.fr
# timeout: 10

class DNSerror(Exception):
    pass

class NullHandler(logging.Handler):
    def emit(self, record):
        pass
nullh = NullHandler()

def sendemail(subject, content):
    msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nX-Mailer: %s\r\nMIME-Version: 1.0\r\nContent-type: text/plain; charset=\"UTF-8\"\r\n\r\n" % \
           (maintainer_address, maintainer_address, ("[%s] " % email_prefix) + subject,
            formatdate(localtime=True), version))
    msg = msg + content + "\r\n"
    server = smtplib.SMTP(mail_server)
    server.set_debuglevel(0)
    server.sendmail(maintainer_address, maintainer_address, msg)
    server.quit()

def get_rr(zone, rrtype, ns_address, handler=None):
    """ rrtype must be a character _string_. handler is a function
    which will be called for each rrset (and receives it as a
    parameter). See display_target for an example of handker (it is
    suitable for a NS rrtype)."""
    mytype = dns.rdatatype.from_text(rrtype)
    query = dns.message.make_query(zone, rrtype)
    query.use_edns(edns=True, payload=edns_size)
    query.want_dnssec(True)
    tests = 0
    while tests < max_tests:
        try:
            response = dns.query.udp(query, ns_address, timeout=2)
            break
        except dns.exception.Timeout:
            tests += 1
            time.sleep(mytimeout * generator.randint(1, 3))
    if tests >= max_tests:
        # TODO: try with TCP, even without truncation? It seems to
        # work with Afilias servers
        default_log.warning("Timeout on %s query for %s on %s" % (rrtype, zone, address))
        sys.exit(1)
    if response.flags & dns.flags.TC: # We were truncated
        response = dns.query.tcp(query, address, timeout=2*mytimeout)
        # TODO: handle the case where the nameserver is broken enough to
        # truncate responses *and* to refuse TCP
    record_found = False
    cursor.execute("BEGIN IMMEDIATE TRANSACTION;"); 
    for rrset in response.answer:
        if rrset.rdtype == mytype:
            record_found = True
            if handler:
                handler(rrset)
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            for thesig in rrset:
                if mytype != dns.rdatatype.DNSKEY and thesig.key_tag not in key_tags:
                     default_log.error("Signed with %s which is not in the key set" % \
                                   thesig.key_tag)
                sig_value = base64.b64encode(thesig.signature)
                cursor.execute("SELECT last_seen FROM Signatures WHERE signature=?;", (sig_value,))
                tuple = cursor.fetchone()
                if tuple is None:   
                    # TODO: store inception and expiration as actual times, not integers
                    cursor.execute("INSERT INTO Signatures (first_seen, last_seen, type, name, ttl, key_tag, algorithm, inception, expiration, signature) VALUES (datetime('now'), datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?);", \
                                   (mytype, zone, rrset.ttl, thesig.key_tag,
                                    thesig.algorithm, thesig.inception, thesig.expiration, sig_value))
                else:
                    cursor.execute("UPDATE Signatures SET last_seen=datetime('now') WHERE signature=?;",
                                   (sig_value,))
    if not record_found:
        default_log.error("No %s at %s" % (rrtype, zone))
        sys.exit(1)
    database.commit()

def display_target(set):
    """ Example of a simple handker for get_rr. """
    for record in set:
        print record.target

def create_key_list(set):
    global keys
    global dnskey_ttl
    keys = []
    dnskey_ttl = set.ttl
    for thekey in set:
        keys.append(thekey)

def update_zones(set):
    serial = set[0].serial
    cursor.execute("SELECT serial FROM Zones WHERE name=? ORDER BY last_seen DESC LIMIT 1;", (zone,))
    tuple = cursor.fetchone()
    if tuple is None or serial != tuple[0]: 
        cursor.execute("INSERT INTO Zones (first_seen, last_seen, name, serial, nameserver) VALUES (datetime('now'), datetime('now'), ?, ?, ?);" , \
                       (zone, serial, address))
    else:
        cursor.execute("UPDATE Zones SET last_seen=datetime('now'), nameserver=? WHERE name=? AND serial=?;", \
                       (address, zone, serial))
        
if len(sys.argv) != 3:
    raise Exception("Usage: dnssec.py zonename nameserver-address")

config = ConfigParser.SafeConfigParser()
config.readfp(open(os.path.expanduser("~/.key-report.ini")))

if config.has_option(SECTION, 'mailserver'):
    mail_server = config.get(SECTION, 'mailserver')
if config.has_option(SECTION, 'prefix'):
    email_prefix = config.get(SECTION, 'prefix')
if config.has_option(SECTION, 'maintainer'):
    maintainer_address = config.get(SECTION, 'maintainer')
if config.has_option(SECTION, 'database'):
    database_name = config.get(SECTION, 'database')
if config.has_option(SECTION, 'timeout'):
    mytimeout = config.getint(SECTION, 'timeout')
if config.has_option(SECTION, 'output'):
    output = config.getboolean(SECTION, 'output')
if config.has_option(SECTION, 'syslog'):
    syslog = config.getboolean(SECTION, 'syslog')

generator = random.Random()
formatter_long = logging.Formatter('%(name)s: %(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S')
formatter_short = logging.Formatter('%(name)s: %(levelname)s %(message)s')
default_log = logging.getLogger('key-store')
if output:
    ch = logging.StreamHandler()
    ch.setFormatter(formatter_long)
    default_log.addHandler(ch)
default_log.setLevel(logging.DEBUG)
if syslog:
    ch = logging.handlers.SysLogHandler("/dev/log")
    ch.setFormatter(formatter_short)
    default_log.addHandler(ch)
if not output and not syslog:
    default_log.addHandler(nullh)
zone = sys.argv[1]
if zone[-1] != '.':
    zone += '.'
address = sys.argv[2]
# TODO: accept as parameter an artificial time, to be used instead of
# the real clock, to test "what if" scenarios?
default_log.info("Starting %s (%s)..." % (zone, address))
error = None
database = sqlite3.connect(database_name) # No need to lock
                                          # ourselves. http://www.sqlite.org/faq.html#q5
cursor = database.cursor()
addresses = []
# TODO: read the database to retrieve the former serial number, to see
# if there was any change?

# TODO: use our own clock rather than SQLite 'now' since
            
get_rr(zone, 'DNSKEY', address, create_key_list)

keys.sort()
key_tags = []
hasher = hashlib.sha1()
for key in keys:
    key_tag = dns.dnssec.key_id(key)
    hasher.update(key.key)
    key_tags.append(key_tag)
    key_value = base64.b64encode(key.key)
    # The AND name is here in case several zones use the same key
    cursor.execute("SELECT key_tag FROM Keys WHERE key=? AND name=?;", (key_value, zone))
    tuple = cursor.fetchone()
    if tuple is None: 
        cursor.execute("INSERT INTO Keys (first_seen, last_seen, name, key_tag, flags, algorithm, protocol, key) VALUES (datetime('now'), datetime('now'), ?, ?, ?, ?, ?, ?);", (zone, key_tag, key.flags, key.algorithm, key.protocol, key_value))
        infos = """
        The key %s appeared for the first time in the zone "%s".

        Its flags are %i and its algorithm %i.
        """ % (key_tag, zone, key.flags, key.algorithm)
        sendemail("New key %s in zone %s" % (key_tag, zone), infos)
    else:
        cursor.execute("UPDATE Keys SET last_seen=datetime('now') WHERE key=? AND name=?;", (key_value, zone))
dnskey_id = base64.b64encode(hasher.digest())
cursor.execute("SELECT id, first_seen, last_seen FROM Keysets WHERE id=? AND name=?;",
               (dnskey_id, zone))
tuple = cursor.fetchone()
if tuple is None:
    cursor.execute("INSERT INTO Keysets (id, first_seen, last_seen, name, ttl) VALUES (?, datetime('now'), datetime('now'), ?, ?);", (dnskey_id, zone, dnskey_ttl))
    # The keyset may already exist, for another zone
    cursor.execute("SELECT id, first_seen, last_seen FROM Keysets WHERE id=?", (dnskey_id,))
    tuple = cursor.fetchone()
    if tuple is None:
        for key in keys:
            cursor.execute("INSERT INTO Keysets_Members (id, member) VALUES (?, ?);", (dnskey_id, base64.b64encode(key.key)))
    infos = """
    The keyset %s appeared for the first time in the zone "%s".

    Its TTL is %i and its members are: %s
        """ % (dnskey_id, zone, dnskey_ttl, key_tags)
    sendemail("New keyset in zone %s" % zone, infos)
else: # This is an already-seen keyset for this zone
    cursor.execute("UPDATE Keysets SET last_seen=datetime('now'), ttl=? WHERE id=? AND name=?;", (dnskey_ttl, dnskey_id, zone))

get_rr(zone, 'SOA',  address, update_zones)

get_rr(zone, 'NS',  address)

cursor.close()
database.close()
default_log.info("Successfully done for %s (%s)" % (zone, address))
