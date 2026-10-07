# Member and config stores

Table and file layouts for database/CSV member and list-config sources.

## Database table structures

**config-table** (for `type: database` list provider):
```sql
CREATE TABLE list_config (
    name   VARCHAR(255) NOT NULL,
    key    VARCHAR(255) NOT NULL,
    value  TEXT,
    PRIMARY KEY (name, key)
);
-- SELECT DISTINCT name FROM list_config          -> all list names
-- SELECT key, value FROM list_config WHERE name = :name  -> list config key-values
```

**members-table** (for `type: database` member resolver). Only `name`, `mail`,
`is_member`, `is_owner` are reserved/structural — `DatabaseMemberResolver` does
`SELECT *` and exposes every other column as a `Member::$attributes` entry
under its own name (see [Member attributes — fully dynamic](../architecture/providers-and-members.md#member-attributes--fully-dynamic)). The columns
below are a sensible starter set, not a fixed schema — add, rename, or remove
freely without touching any code:
```sql
CREATE TABLE list_members (
    name       VARCHAR(255) NOT NULL,  -- list name
    mail       VARCHAR(255) NOT NULL,
    firstname  VARCHAR(255) NULL,
    lastname   VARCHAR(255) NULL,
    username   VARCHAR(255) NULL,
    pronoun    VARCHAR(255) NULL,
    is_member  TINYINT(1) NOT NULL DEFAULT 1,
    is_owner   TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (name, mail)
);
-- SELECT * FROM list_members WHERE name = :name AND is_member = 1  -> members
-- SELECT * FROM list_members WHERE name = :name AND is_owner = 1   -> owners
```

## CSV member file format

For `member-resolver: {type: csv, file: ...}`. Same shape as `members-table` above,
one file shared across all lists using this resolver, scoped by the `name` column.
Only `name`/`mail`/`is_member`/`is_owner` are reserved — every other header
column is exposed as an attribute under its own name, and `addMember()` adds
new columns on demand (backfilling `''` elsewhere) — see "Member attributes —
fully dynamic":

```csv
name,mail,firstname,lastname,username,pronoun,is_member,is_owner
mylist,alice@example.org,Alice,Example,alice,she,1,0
mylist,bob@example.org,,,,,1,0
otherlist,carol@example.org,Carol,Example,carol,,1,1
```

Non-reserved columns may be empty. `is_member`/`is_owner` are `0`/`1`;
missing `is_member` defaults to `1`, missing `is_owner` defaults to `0`. The file is
created on first write if it doesn't exist yet.
