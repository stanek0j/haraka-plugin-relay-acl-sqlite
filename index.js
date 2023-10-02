const ipaddr = require('ipaddr.js');
let sqlite3;
let domainSelect;
let aclsSelect;

exports.register = function () {
    try {
        sqlite3 = require('better-sqlite3');
    }
    catch (e) {
        this.logerror(e);
        this.logerror("unable to load better-sqlite3, try\n\n\t'npm install -g better-sqlite3'\n\n");
        return;
    }

    this.load_relay_acl_sqlite_ini();

    this.register_hook('mail', 'check_acl');
}

exports.load_relay_acl_sqlite_ini = function () {
    const plugin = this;
    plugin.cfg = plugin.config.get('relay_acl_sqlite.ini', function () {
        plugin.load_relay_acl_sqlite_ini();
    });
}

exports.check_acl = function (next, connection, params) {
    const plugin = this;
    const dbName = plugin.cfg.main.db_file || 'relay_acl.db';

    // handle relaying only
    if (!connection.relaying) {
        return next();
    }

    let action;

    try {
        const db = new sqlite3(dbName, { readonly: true, fileMustExist: true });
        domainSelect = db.prepare("SELECT domain,implicit,enabled FROM relay_domains WHERE domain=?");
        aclsSelect = db.prepare("SELECT sequence,user,ip,action FROM relay_acls WHERE domain=? ORDER BY sequence ASC");

        // find source domain in db
        const domain = domainSelect.get(params[0].host);
        if (domain) {
            connection.lognotice(plugin, `Domain '${params[0].host}' found.`);
            // handle domain if enabled
            if (domain.enabled) {
                let skip = false;
                // look through ACLs for a match
                const acls = aclsSelect.all(domain.domain);
                acls.forEach(acl => {
                    if (skip) {
                        return;
                    }
                    connection.logdebug(plugin, `ACL: ${acl.sequence.toString().trim(3).padStart(3)} user: ${acl.user} ip: ${acl.ip} ${acl.action ? 'permit' : 'deny'}`);
                    let match = true;
                    if (acl.user !== null && acl.user !== connection.notes.auth_user) {
                        match = false;
                    }
                    if (acl.ip !== null) {
                        const parts = acl.ip.split('/');
                        const ip = parts[0];
                        const mask = parseInt(parts[1]);
                        if (!ipaddr.parse(connection.remote.ip).match(ipaddr.parse(ip), mask)) {
                            match = false;
                        }
                    }
                    if (match) {
                        connection.logdebug(plugin, 'ACL: MATCHED!');
                        action = acl.action ? CONT : DENY;
                        if (acl.action) {
                            connection.lognotice(plugin, `ACL[${acl.sequence}] PERMIT.`);
                            connection.transaction.results.add(plugin, {pass: 'acl', msg: 'acl(permit)', emit: true});
                        }
                        else {
                            connection.lognotice(plugin, `ACL[${acl.sequence}] DENY.`);
                            connection.transaction.results.add(plugin, {fail: 'acl', msg: 'acl(deny)', emit: true});
                        }
                        skip = true;
                        return;
                    }
                });
                // handle default domain action
                if (typeof action === 'undefined') {
                    connection.lognotice(plugin, 'No ACL matched, using domain implicit action.');
                    action = domain.implicit ? CONT : DENY;
                    if (domain.implicit) {
                        connection.lognotice(plugin, 'Domain implicit PERMIT.');
                        connection.transaction.results.add(plugin, {pass: 'domain', msg: 'domain(permit)', emit: true});
                    }
                    else {
                        connection.lognotice(plugin, 'Domain implicit DENY.');
                        connection.transaction.results.add(plugin, {fail: 'domain', msg: 'domain(deny)', emit: true});
                    }
                }
            }
            else {
                connection.lognotice(plugin, `Domain '${params[0].host}' disabled.`);
            }
        }
        else {
            connection.lognotice(plugin, `Domain '${params[0].host}' not in database.`);
        }

        db.close();
    }
    catch (e) {
        connection.transaction.results.add(plugin, {err: e.message});
    }

    // handle matched action
    if (typeof action !== 'undefined') {
        return next(action);
    }

    // handle global default action
    connection.logdebug(plugin, 'No match so far, implicit action handling.');
    switch (plugin.cfg.main.default_handle) {
        case 'permit':
            action = CONT;
            connection.transaction.results.add(plugin, {pass: 'implicit', msg: 'implicit(permit)', emit: true});
            break;
        case 'deny':
            action = DENY;
            connection.transaction.results.add(plugin, {fail: 'implicit', msg: 'implicit(deny)', emit: true});
            break;
        case 'skip':
        default:
            action = CONT;
            connection.transaction.results.add(plugin, {skip: 'implicit', msg: 'implicit(skip)', emit: true});
            break;
    }

    return next(action);
}
