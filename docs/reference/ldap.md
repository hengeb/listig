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

Multiple `list-providers` are supported. If the same list `cn` appears in more than one provider, behaviour is undefined.
