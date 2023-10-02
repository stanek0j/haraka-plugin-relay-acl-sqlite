[![NPM][npm-img]][npm-url]

# haraka-plugin-relay-acl-sqlite

This plugin enables greater control for relaying mails. ACLs are specified for each source domain separately. Rules may be matched based on authenticated username and/or IP source address. Domains and ACL rules are stored in SQLite database.

##Configuration

Configuration is stored in `config/relay_acl_sqlite.ini` and uses the INI style formatting.

Variable `db_file` should point to a database file. Implicit action should be defined as `default_handle` and may contain either **permit**, **deny** or **skip**. This action is taken when no domain is matched or a domain is disabled.

Example:

```
db_file=relay_acl.db
default_handle=skip
```

## Managing domains and ACLs

Simple tool for managing domains and ACLs in database is provided. Syntax for the tool is:

`node ./manage.js [command] <args>`

### List

For listing all domains in database, use:

`node ./manage.js list`

Adding option `-a` adds ACLs to the output.

### Domains

First of all it is necessary to define domains that should be handled. Syntax for managing domains is:

`node ./manage.js domain <action> <domain>`

Possible actions are **add** for adding new domain, **mod** for changing existing domain and **del** for removing a domain.

Options are:
- `-e` | `-d` - enable/disable domain
- `-p` | `-x` - implicit permit/deny for domain

### ACLs

For each domain an access control list (ACL) is created. For each ACL it is possible to define rule matching by username and/or IP address/range. Both IPv4 and IPv6 are supported. If both username and IP address/range are defined, it is necessary for both of them to be matched (as if logical `AND` operation). Syntax:

`node ./manage acl <action> <domain>`

Possible actions are **add** for creating new ACL rule, **mod** for changing existing ACL rule and **del** for removing ACL rule. To modify or delete ACL rule, it is necessary to identify an existing ACL rule by sequence number.

Options are:
- `-s` - sequence number
- `-u` - username
- `-i` - IP address or range
- `-p` | `-x` - result on match, either permit or deny

## Example

Let's say we have a domain **example.com**. Implicit rule should be to deny everything. Issued commands are as follows. Some output may be omitted or truncated.

```bash
> node ./manage.js domain add example.com -x
> node ./manage.js list
List of domains:


  [>]  example.com
    \________________________
      [ enabled  ][  deny  ]

```

Next step is to populate ACLs for both domains. We want to:
1) allow any user from localhost,
2) user **alice** should be allowed from IPv4 range 192.0.2.0/24
3) user **bob** should be denied

```bash
> node ./manage.js acl add example.com -i 127.0.0.1 -p
> node ./manage.js acl add example.com -i ::1 -p
> node ./manage.js acl add example.com -u alice -i 192.0.2.0/24 -p
> node ./manage.js acl add example.com -u bob -x
> node ./manage.js list -a
List of domains:


  [>]  example.com
    \________________________
      [ enabled  ][  deny  ]

      _____ _______ ______________ ________
     | seq | user  |      ip      | action |
      ===== ======= ============== ========
     |  10 |       | 127.0.0.1/32 | permit |
      ----- ------- -------------- --------
     |  20 |       | ::1/128      | permit |
      ----- ------- -------------- --------
     |  30 | alice | 192.0.2.0/24 | permit |
      ----- ------- -------------- --------
     |  40 | bob   |              |  deny  |
      ----- ------- -------------- --------

```

After entering the rules you may notice that the last rule is not necessary so let's remove it. Let's also add rules to deny **bob** from localhost. These rules need to be applied at the beginning. Also, for **alice** new IPv4 range should be 192.168.0.0/16.

```bash
> node ./manage.js acl del example.com -s 40
> node ./manage.js acl add example.com -u bob -i 127.0.0.1 -s 1 -x
> node ./manage.js acl add example.com -u bob -i ::1 -s 2 -x
> node ./manage.js acl mod example.com -s 30 -i 192.168.0.0/16
> node ./manage.js list -a
List of domains:


  [>]  example.com
    \________________________
      [ enabled  ][  deny  ]

      _____ _______ ________________ ________
     | seq | user  |       ip       | action |
      ===== ======= ================ ========
     |   1 | bob   | 127.0.0.1/32   |  deny  |
      ----- ------- ---------------- --------
     |   2 | bob   | ::1/128        |  deny  |
      ----- ------- ---------------- --------
     |  10 |       | 127.0.0.1/32   | permit |
      ----- ------- ---------------- --------
     |  20 |       | ::1/128        | permit |
      ----- ------- ---------------- --------
     |  30 | alice | 192.168.0.0/16 | permit |
      ----- ------- ---------------- --------

```


[npm-img]: https://nodei.co/npm/haraka-plugin-relay-acl-sqlite.png
[npm-url]: https://www.npmjs.com/package/haraka-plugin-relay-acl-sqlite
