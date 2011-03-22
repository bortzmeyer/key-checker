#!/usr/bin/python

""" Displays the keyset of a zone """

database_name = "dnssec.sqlite"

import sys
import sqlite3

if len(sys.argv) != 2:
    raise Exception("Usage: keyset-zone.py zone")
zone = sys.argv[1]
if zone[-1] != '.':
    zone += '.'

database = sqlite3.connect(database_name) 
ecursor = database.cursor()
icursor = database.cursor()
i = 0
ecursor.execute("SELECT id, first_seen, last_seen FROM Keysets;")
for keyset_tuple in ecursor.fetchall():
    keyset_id = keyset_tuple[0]
    first = keyset_tuple[1] # SQLite stores them in UTC, remember
    last = keyset_tuple[2]
    icursor.execute("""SELECT key_tag, flags FROM Keysets_members, Keysets, Keys
                             WHERE Keys.name=? AND Keysets.name=?
                                    AND Keysets.id = Keysets_members.id AND Keysets.id=?
                                    AND Keys.key=Keysets_members.member;""",
                    (zone, zone, keyset_id,))
    keys_ok = False
    key_tags = []
    for key_tuple in icursor.fetchall():
        if not keys_ok:
            i += 1
            keys_ok = True
        key_tag = key_tuple[0]
        flags = key_tuple[1]
        if flags & 0x1:
            ksk = "*"
        else:
            ksk = ""
        key_tags.append("%i%s" % (key_tag, ksk))
    if keys_ok:
        print "#%i of %s: %s\t(first %sZ, last %sZ)" % (i, zone, key_tags, first, last)
ecursor.close()
icursor.close()
database.rollback() # Just in case
database.close()

