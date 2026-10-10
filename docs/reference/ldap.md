# LDAP structure

How lists are stored in LDAP.

## LDAP Structure

Lists are stored as `mailGroup` objects. This objectClass provides the `mail` attribute.

```
dn: cn=mylist,ou=lists,dc=example,dc=org
objectClass: mailGroup
cn: mylist
mail: mylist@example.org
member: uid=alice,ou=users,dc=example,dc=org
member: uid=bob,ou=users,dc=example,dc=org
owner: uid=carol,ou=users,dc=example,dc=org
description: reply-to:sender
description: personalize:firstname,username
description: archive:members
```

Member and owner DNs are resolved to email addresses and display names via `LdapService`.
All other components receive a `ListConfig` object — they have no knowledge of LDAP.
IMAP password stored encrypted: `password:base64(iv):base64(ciphertext)`.

## Finding a list's group, and empty groups

Listig reads and changes a list's `member` attribute on the group entry found under `ldap-list-dn` (the directory's base DN when unset) that matches `ldap-filter` (default `(objectClass=mailGroup)`) **and** has the list's `cn` — the same place and filter that discover the lists. An entry elsewhere that merely shares the `cn` (a person, another kind of group) is never taken for the list's group. (`member-resolver: {type: ldap}` inside a non-LDAP provider keeps matching by `cn` alone under its base DN unless it sets `ldap-list-dn`/`ldap-filter` too.)

A schema that requires at least one `member` (e.g. `groupOfNames`) would reject removing the last one. Set the provider key `ldap-empty-group-member` to the DN of a **placeholder entry** — a user without a `mail` attribute:

```
dn: uid=nobody,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
uid: nobody
cn: nobody
sn: nobody
```

```yaml
list-providers:
  staff:
    type: ldap
    ldap-empty-group-member: uid=nobody,ou=users,dc=example,dc=org
```

Listig then adds the placeholder to `member` before it removes the last real member, removes it again when a real member is added, and never reports it as a member or recipient. Without the key, removing the last member is simply attempted (which works for schemas where `member` is optional) and a rejection by the server is logged and reported as a failed removal.

Multiple `list-providers` are supported. If the same list `cn` appears in more than one provider, behaviour is undefined.
