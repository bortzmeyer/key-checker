-- Columns storing time are of type INT because SQLite doesn't provide
-- better. The time is always stored in UTC.

-- TODO: add primary keys (such as the couple (key, name) for the tables Keys)

CREATE TABLE Signatures (first_seen INT, last_seen INT, type INT, name TEXT, 
       ttl INT, key_tag INT, algorithm INT, inception INT, expiration INT, signature TEXT);

CREATE TABLE Zones (first_seen INT, last_seen INT, name TEXT,
        serial INT, nameserver TEXT); -- TODO: not perfect because the
				      -- nameserver may change each
				      -- time. A table with all the
				      -- measures instead?

CREATE TABLE Keys (first_seen INT, last_seen INT, name TEXT, key_tag INT, flags INT, algorithm INT, protocol INT, key TEXT);

-- Each DNSKEY RRset is made of several lines of table Keysets, one
-- for each member key. All the lines of a given DNSKEY RRset has the
-- same "id".
-- Remember that two zones may have the same keyset so we cannot make id UNIQUE
CREATE TABLE Keysets (id TEXT NOT NULL, first_seen INT, last_seen INT, name TEXT, ttl INT, PRIMARY KEY (id, name));
-- "id" is the SHA-1 hash (base64-encoded) of all the keys of the set.
CREATE TABLE Keysets_members (id TEXT, member TEXT);
-- "member" refers to a "key" in table Keys

-- Good readings, for the "time" columns:
-- http://www.sqlite.org/datatype3.html and
-- http://www.sqlite.org/lang_datefunc.html
