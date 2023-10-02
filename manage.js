#!/usr/bin/env node

const net = require('net');
const yargs = require('yargs');
const sqlite3 = require('better-sqlite3');
const harakaConfig = require('haraka-config');

const config = harakaConfig.get('relay_acl_sqlite.ini');
const dbName = config.main.db_file || 'relay_acl.db';
const db = new sqlite3(dbName);
process.on('exit', () => db.close());

const create1 = db.prepare("CREATE TABLE IF NOT EXISTS relay_domains (domain TEXT NOT NULL UNIQUE, implicit INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(domain)) WITHOUT ROWID");
const create2 = db.prepare("CREATE TABLE IF NOT EXISTS relay_acls (domain TEXT NOT NULL, sequence INTEGER NOT NULL DEFAULT 0, user TEXT, ip TEXT, action INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(domain) REFERENCES relay_domains(domain) ON UPDATE CASCADE ON DELETE CASCADE, PRIMARY KEY(domain,sequence))");
create1.run();
create2.run();

const domainsSelect = db.prepare("SELECT domain,implicit,enabled FROM relay_domains");
const domainSelect = db.prepare("SELECT domain,implicit,enabled FROM relay_domains WHERE domain=?");
const domainInsert = db.prepare("INSERT INTO relay_domains (domain,implicit,enabled) VALUES (?,?,?)");
const domainUpdateImplicit = db.prepare("UPDATE relay_domains SET implicit=? WHERE domain=?");
const domainUpdateEnabled = db.prepare("UPDATE relay_domains SET enabled=? WHERE domain=?");
const domainRemove = db.prepare("DELETE FROM relay_domains WHERE domain=?");

const aclsSelect = db.prepare("SELECT sequence,user,ip,action FROM relay_acls WHERE domain=? ORDER BY sequence ASC");
const aclsCheckSeq = db.prepare("SELECT MAX(sequence) AS max FROM relay_acls WHERE domain=?");
const aclExists = db.prepare("SELECT COUNT(*) AS has FROM relay_acls WHERE domain=? AND sequence=?");
const aclInsert = db.prepare("INSERT INTO relay_acls (domain,sequence,user,ip,action) VALUES (?,?,?,?,?)");
const aclUpdateUser = db.prepare("UPDATE relay_acls SET user=? WHERE domain=? AND sequence=?");
const aclUpdateIp = db.prepare("UPDATE relay_acls SET ip=? WHERE domain=? AND sequence=?");
const aclUpdateAction = db.prepare("UPDATE relay_acls SET action=? WHERE domain=? AND sequence=?");
const aclRemove = db.prepare("DELETE FROM relay_acls WHERE domain=? AND sequence=?");

function listDomains () {
    return domainsSelect.all();
}

function listDomain (domain) {
    return domainSelect.get(domain);
}

function addDomain (domain, implicit, enabled) {
    return domainInsert.run(domain, implicit, enabled);
}

function modDomainImplicit (domain, implicit) {
    return domainUpdateImplicit.run(implicit, domain);
}

function modDomainEnabled (domain, enabled) {
    return domainUpdateEnabled.run(enabled, domain);
}

function delDomain (domain) {
    return domainRemove.run(domain);
}

function listAcls (domain) {
    return aclsSelect.all(domain);
}

function nextSequenceAcl (domain) {
    return aclsCheckSeq.get(domain);
}

function hasAcl (domain, seq) {
    return aclExists.get(domain, seq);
}

function addAcl (domain, seq, user, ip, action) {
    return aclInsert.run(domain, seq, user, ip, action);
}

function modAclUser (domain, seq, user) {
    return aclUpdateUser.run(user, domain, seq);
}

function modAclIp (domain, seq, ip) {
    return aclUpdateIp.run(ip, domain, seq);
}

function modAclAction (domain, seq, action) {
    return aclUpdateAction.run(action, domain, seq);
}

function delAcl (domain, seq) {
    return aclRemove.run(domain, seq);
}

function validateHostname (hostname) {
    if (typeof hostname !== 'string') {
        return false;
    }

    const chars = /^[a-zA-Z0-9-.]{1,253}\.?$/g
    if (!chars.test(hostname)) {
        return false;
    }

    if (hostname.endsWith('.')) {
        hostname = hostname.slice(0, hostname.length - 1);
    }

    const labels = hostname.split('.');
    const valid = labels.every(function (label) {
        const labelChars = /^([a-zA-Z0-9-]+)$/g
        return (labelChars.test(label) && label.length < 64 && !label.startsWith('-') && !label.endsWith('-'));
    });

    return valid;
}

function validateSequenceNumber (number) {
    if (typeof number !== 'number') {
        return false;
    }

    return (number >=0 && number < 1000);
}

function parseIpAddress (address) {
    let ip = false; let mask = false;

    const parts = address.split('/');

    if (net.isIP(parts[0])) {
        ip = parts[0];
        if (parts[1]) {
            mask = parseInt(parts[1]);
        }
        else {
            if (net.isIPv4(parts[0])) {
                mask = 32;
            }
            else if (net.isIPv6(parts[0])) {
                mask = 128;
            }
        }
    }

    return [ip, mask];
}

function validateIpAddress (ip, mask) {
    if (ip === false || mask === false || isNaN(mask)) {
        return false;
    }

    if (ip === null && mask === null) {
        return true;
    }

    if (!net.isIP(ip)) {
        return false;
    }

    if (net.isIPv4(ip) && (mask < 0 || mask > 32)) {
        return false;
    }
    if (net.isIPv6(ip) && (mask < 0 || mask > 128)) {
        return false;
    }

    return true;
}

function displayDomain (domain) {
    console.log();
    console.log(`  [>]  ${domain.domain}`);
    console.log(`    \\________________________`);
    console.log(`      [ ${domain.enabled ? 'enabled ' : 'disabled'} ][ ${domain.implicit ? 'permit' : ' deny '} ]`);
    console.log();
}

function displayAclHead (lenUser, lenIp) {
    console.log(`      _____ _${''.padEnd(lenUser, '_')}_ _${''.padEnd(lenIp, '_')}_ ________`);
    console.log(`     | seq | ${'user'.padStart(Math.floor(lenUser/2+2)).padEnd(Math.ceil(lenUser))} | ${'ip'.padStart(Math.floor(lenIp/2+1)).padEnd(Math.ceil(lenIp))} | action |`);
    console.log(`      ===== =${''.padEnd(lenUser, '=')}= =${''.padEnd(lenIp, '=')}= ========`);
}

function displayAclLine (acl, lenUser, lenIp) {
    console.log(`     | ${acl.sequence.toString().trim(3).padStart(3)} | ${(acl.user ? acl.user : '').padEnd(lenUser)} | ${(acl.ip ? acl.ip : '').padEnd(lenIp)} | ${acl.action ? 'permit' : ' deny '} |`);
    console.log(`      ----- -${''.padEnd(lenUser, '-')}- -${''.padEnd(lenIp, '-')}- --------`);
}

function displayAclTable (domain) {
    const acls = listAcls(domain);
    let lenUser = 4;
    let lenIp = 2;
    acls.forEach(acl => {
        if (acl.user && acl.user.length > lenUser) {
            lenUser = acl.user.length;
        }
        if (acl.ip && acl.ip.length > lenIp) {
            lenIp = acl.ip.length;
        }
    });
    displayAclHead(lenUser, lenIp);
    acls.forEach(acl => {
        displayAclLine(acl, lenUser, lenIp);
    });
    console.log();
}

yargs
    .usage("Usage: $0 [cmd] <args>").alias("h", "help")
    .command(
        'list [domain]',
        'List single/all domains',
        (args) => {
            args.positional('domain', {
                describe: 'domain to list',
                type: 'string',
            });
            args.option('a', {
                alias: 'acls',
                describe: 'include ACLs',
                type: 'boolean'
            });
        },
        (argv) => {
            try {
                console.log('List of domains:\n');
                let rows;
                if (argv.domain) {
                    rows = listDomain(argv.domain);
                    if (!rows) {
                        console.error(`Domain "${argv.domain}" not found.`);
                        return;
                    }
                    rows = [rows];
                }
                else {
                    rows = listDomains();
                }
                rows.forEach(domain => {
                    displayDomain(domain);
                    if (argv.a) {
                        displayAclTable(domain.domain);
                    }
                });
            }
            catch (err) {
                console.error(`Unexpected error: ${err.message}`);
            }
        })
    .command(
        'domain <action> <domain>',
        'Handle domains',
        (args) => {
            args.positional('action', {
                choices: ['add', 'mod', 'del'],
                demandOption: true,
                describe: 'Action to choose'
            });
            args.positional('domain', {
                demandOption: true,
                describe: 'Domain name',
                type: 'string'
            });
            args.option('e', {
                alias: 'enable',
                conflicts: 'd',
                describe: 'Enable domain ACLs',
                type: 'boolean'
            });
            args.option('d', {
                alias: 'disable',
                conflicts: 'e',
                describe: 'Disable domain ACLs',
                type: 'boolean'
            });
            args.option('p', {
                alias: 'permit',
                conflicts: 'x',
                describe: 'Domain implicit permit',
                type: 'boolean'
            });
            args.option('x', {
                alias: 'deny',
                conflicts: 'p',
                describe: 'Domain implicit deny',
                type: 'boolean'
            });
        },
        (argv) => {
            try {
                if (!validateHostname(argv.domain)) {
                    console.error(`Domain "${argv.domain}" is not a valid hostname.`);
                    return;
                }
                let message = 'not found';
                const implicit = (!argv.p && !argv.x) ? 1 : argv.p ? 1 : 0;
                const enabled = (!argv.e && !argv.d) ? 1 : argv.e ? 1 : 0;
                switch (argv.action) {
                    case 'add':
                        addDomain(argv.domain, implicit, enabled);
                        break;
                    case 'mod':
                        if (argv.p || argv.x) {
                            modDomainImplicit(argv.domain, implicit);
                        }
                        if (argv.e || argv.d) {
                            modDomainEnabled(argv.domain, enabled);
                        }
                        break;
                    case 'del':
                        if (delDomain(argv.domain).changes > 0) {
                            message = 'deleted';
                        }
                        break;
                }
                const row = listDomain(argv.domain);
                if (row) {
                    displayDomain(row);
                }
                else {
                    console.log(`Domain "${argv.domain}" ${message}.`);
                }
            }
            catch (err) {
                console.error(`Unexpected error: ${err.message}`);
            }
        })
    .command(
        'acl <action> <domain>',
        'Handle access list entries',
        (args) => {
            args.positional('action', {
                choices: ['add', 'mod', 'del'],
                demandOption: true,
                describe: 'Action to choose'
            });
            args.positional('domain', {
                demandOption: true,
                describe: 'Domain name',
                type: 'string'
            });
            args.option('s', {
                alias: 'seq',
                describe: 'Sequence number',
                type: 'number'
            });
            args.option('u', {
                alias: 'user',
                describe: 'Name of user',
                type: 'string'
            });
            args.option('i', {
                alias: 'ip',
                describe: 'IP address or range in CIDR',
                type: 'string'
            });
            args.option('p', {
                alias: 'permit',
                conflicts: 'x',
                describe: 'Result on match',
                type: 'boolean'
            });
            args.option('x', {
                alias: 'deny',
                conflicts: 'p',
                describe: 'Result on match',
                type: 'boolean'
            });
        },
        (argv) => {
            try {
                if (!validateHostname(argv.domain)) {
                    console.error(`Domain "${argv.domain}" is not a valid hostname.`);
                    return;
                }
                const row = listDomain(argv.domain);
                if (row) {
                    const user = (typeof argv.u === 'undefined') ? null : argv.u ? argv.u : null;
                    const [ip, mask] = (typeof argv.i === 'undefined') ? [null, null] : argv.i ? parseIpAddress(argv.i) : [null, null];
                    const action = (!argv.p && !argv.x) ? 1 : argv.p ? 1 : 0;
                    let maxSeq; let nextSeq; let seq;
                    switch (argv.action) {
                        case 'add':
                            maxSeq = nextSequenceAcl(argv.domain).max;
                            nextSeq = maxSeq + 10 - (maxSeq % 10);
                            seq = (typeof argv.s !== 'undefined') ? argv.s : nextSeq;
                            if (seq === nextSeq && seq >= 1000) {
                                console.error('Unable to determine sequence number automatically. Use manual assignment.');
                                return;
                            }
                            if (!validateSequenceNumber(seq)) {
                                console.error('Sequence number not in range 0 <= x < 1000.');
                                return;
                            }
                            if (!validateIpAddress(ip, mask)) {
                                console.error('Not a valid IP address or range.');
                                return;
                            }
                            if (!hasAcl(argv.domain, seq).has) {

                                addAcl(argv.domain, seq, user, (ip === null) ? null : `${ip  }/${  mask}`, action);
                            }
                            else {
                                console.error(`ACL with sequence number ${seq} already exists.`);
                                return;
                            }
                            break;
                        case 'mod':
                            if (typeof argv.s === 'undefined') {
                                console.error('Sequence number not specified.');
                                return;
                            }
                            if (!validateSequenceNumber(argv.s)) {
                                console.error('Sequence number not in range 0 <= x < 1000.');
                                return;
                            }
                            if (!validateIpAddress(ip, mask)) {
                                console.error('Not a valid IP address or range.');
                                return;
                            }
                            if (!hasAcl(argv.domain, argv.s).has) {
                                console.error(`ACL with sequence number ${seq} does not exist.`);
                                return;
                            }
                            if (typeof argv.u !== 'undefined') {
                                modAclUser(argv.domain, argv.s, user);
                            }
                            if (typeof argv.i !== 'undefined') {
                                modAclIp(argv.domain, argv.s, `${ip  }/${  mask}`);
                            }
                            if (argv.p || argv.x) {
                                modAclAction(argv.domain, argv.s, action);
                            }
                            break;
                        case 'del':
                            if (typeof argv.s === 'undefined') {
                                console.error('Sequence number not specified.');
                                return;
                            }
                            if (!validateSequenceNumber(argv.s)) {
                                console.error('Sequence number not in range 0 <= x < 1000.');
                                return;
                            }
                            if (delAcl(argv.domain, argv.s).changes > 0) {
                                console.log('ACL rule deleted.');
                            }
                            else {
                                console.error('ACL rule not found.');
                                return;
                            }
                            break;
                    }
                    displayDomain(row);
                    displayAclTable(argv.domain);
                }
                else {
                    console.log(`Domain "${argv.domain}" not found.`);
                }
            }
            catch (err) {
                console.error(`Unexpected error: ${err.message}`);
            }
        })
    .help().demandCommand().argv;

