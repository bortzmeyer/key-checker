#!/usr/bin/env python

""" Checks the entire database to see if all the key rollovers
followed the proper timing."""

database_name = "dnssec.sqlite"
verbose = False
order = 'time' # 'time' or 'name'

import sys
import sqlite3

database = sqlite3.connect(database_name) 
zone_cursor = database.cursor()
key_cursor = database.cursor()
keyset_cursor = database.cursor()
sig_cursor = database.cursor()
resig_cursor = database.cursor()
problems = {}

def test_zone(zone):
    if verbose:
        print "Testing %s..." % zone
    key_cursor.execute("SELECT key_tag, key, flags, first_seen, last_seen FROM Keys WHERE name=?;", [zone, ])
    for key_tuple in key_cursor.fetchall():
        key_tag = key_tuple[0]
        key = key_tuple[1]
        flags = key_tuple[2]
        first_seen = key_tuple[3]
        last_seen = key_tuple[4]
        ksk = flags & 0x1
        if not ksk: # TODO: test the KSK as well
            if verbose:
                print "\tFor key %s first seen at %s..." % (key_tag, first_seen)
            keyset_cursor.execute("""SELECT DISTINCT Keysets.id, 
                                           first_seen, last_seen, ttl
                                       FROM Keysets, Keysets_members
                                       WHERE Keysets.id NOT IN
                                            (SELECT DISTINCT id FROM Keysets_members
                                                      WHERE member=?)
                                          AND Keysets.id = Keysets_members.id
                                          AND Keysets.name = ?
                                          AND datetime(strftime('%s', first_seen),
                                                       'unixepoch') <=
                                              datetime(strftime('%s', ?),
                                                       'unixepoch')     
                                      ORDER by last_seen DESC LIMIT 1;""",
                                  [key, zone, first_seen])  
            reference_time = None
            for keyset_tuple in keyset_cursor.fetchall():
                keyset = keyset_tuple[0]
                first = keyset_tuple[1]
                last = keyset_tuple[2]
                reference_time = last
                ttl = int(keyset_tuple[3])
                if verbose:
                    print "\t\tLast previous keyset before %s: %s (TTL %i)" % (keyset, last, ttl)
            if reference_time is not None:
                sig_cursor.execute("""SELECT first_seen, type FROM Signatures
                                          WHERE key_tag=? AND name=?
                                             AND type != 48 
                                             AND datetime(strftime('%s',first_seen),
                                                                   'unixepoch') <
                                                 datetime((strftime('%s',?) + ?),
                                                                   'unixepoch')
                                        ORDER BY first_seen LIMIT 1;""",
                                   [key_tag, zone, reference_time, ttl])
                for sig_tuple in sig_cursor.fetchall():
                    first_sig = sig_tuple[0]
                    tipe = int(sig_tuple[1])
                    # The test can be wrong if there are *several*
                    # signatures (isc.org does that) and others are
                    # done with an older key. A validating resolver
                    # can choose its policy when there are multiple
                    # signatures (RFC 4035 5.3.3) but it is only when
                    # some are valid and some are not. For the case of
                    # unvalidatable sigs because of a missing key, see
                    # RFC 4035 4.3 and 5. It is legal to have broken
                    # chains of trust.
                    if verbose:
                        print "\t\tSearching sig done on %s for type %s like %s..." % (first_sig, tipe, key_tag)
                    resig_cursor.execute("""SELECT key_tag FROM Signatures
                                 WHERE name=? AND type=? AND key_tag!=? AND first_seen=?;""",
                                         [zone, tipe, key_tag, first_sig])
                    doublesig_tuple = resig_cursor.fetchone()
                    if doublesig_tuple is None:
                        if order == 'name':
                            index = zone + reference_time
                        else:
                            index = reference_time + zone
                        problems[index] = "ERROR: signature of zone %s first seen at %s while the last keyset before key %s was last seen at %s and its TTL was %i" % (zone, first_sig, key_tag, reference_time, ttl)
            if verbose:
                print "\tFor key %s last seen at %s..." % (key_tag, last_seen)
            keyset_cursor.execute("""SELECT DISTINCT Keysets.id, first_seen, last_seen
                                       FROM Keysets, Keysets_members
                                       WHERE Keysets.id NOT IN
                                            (SELECT DISTINCT id FROM Keysets_members
                                                      WHERE member=?)
                                          AND Keysets.id = Keysets_members.id
                                          AND Keysets.name = ?
                                          AND datetime(strftime('%s', first_seen),
                                                       'unixepoch') >=
                                              datetime(strftime('%s', ?),
                                                       'unixepoch')     
                                      ORDER by first_seen LIMIT 1;""",
                                  [key, zone, first_seen])
            reference_time = None
            for keyset_tuple in keyset_cursor.fetchall():
                keyset = keyset_tuple[0]
                first = keyset_tuple[1]
                reference_time = first
                last = keyset_tuple[2]
                if verbose:
                    print "\t\tFirst keyset after %s: %s" % (keyset, first)
            if reference_time is not None:
                # Otherwise, it simply means the key was not retired yet
                # 48 : DNSKEY, a special case
                sig_cursor.execute("""SELECT last_seen, type, ttl FROM Signatures
                                          WHERE key_tag=? AND name=?
                                             AND type != 48 
                                             AND datetime(strftime('%s',last_seen)+ttl,
                                                                   'unixepoch') >=
                                                 datetime(strftime('%s',?),
                                                                   'unixepoch')
                                        ORDER BY last_seen DESC LIMIT 1;""",
                                   [key_tag, zone, reference_time])
                for sig_tuple in sig_cursor.fetchall():
                    last = sig_tuple[0]
                    tipe = int(sig_tuple[1])
                    ttl = int(sig_tuple[2])
                    if verbose:
                        print "\t\tSearching sig done on %s for type %s like %s..." % (last, tipe, key_tag)
                    # Test for the case of a double-signature
                    resig_cursor.execute("""SELECT key_tag FROM Signatures
                                 WHERE name=? AND type=? AND key_tag!=? AND last_seen=?;""",
                                         [zone, tipe, key_tag, last])
                    doublesig_tuple = resig_cursor.fetchone()
                    if doublesig_tuple is None:
                        if order == 'name':
                            index = zone + reference_time
                        else:
                            index = reference_time + zone
                        problems[index] = "ERROR: signature of zone %s last seen at %s (with a TTL of %i) while the key %s was retired at %s" % (zone, last, ttl, key_tag, reference_time)

if order != 'name' and order != 'time':
    print "Invalid sorting criteria \"%s\"" % order
if len(sys.argv) <= 1:
    zone_cursor.execute("SELECT DISTINCT name from Zones;")
    for zone_tuple in zone_cursor.fetchall():
        zone = zone_tuple[0]
        test_zone(zone)
else:
    for zone in sys.argv[1:]:
        if zone[-1:len(zone)] != '.':
            zone = zone + '.'
        test_zone(zone)
problem_keys = problems.keys()
problem_keys.sort()
for problem in problem_keys:
    print problems[problem]
database.close()


