
// node.js built-in modules
const assert   = require('assert');

// npm modules
const fixtures = require('haraka-test-fixtures');

// start of tests
//    assert: https://nodejs.org/api/assert.html
//    mocha: http://mochajs.org

beforeEach(function (done) {
    this.plugin = new fixtures.plugin('relay-acl-sqlite');
    done();  // if a test hangs, assure you called done()
});

describe('', function () {
    it('loads', function (done) {
        assert.ok(this.plugin);
        done();
    });
});

describe('load_ini', function () {
    it('loads .ini from config/relay_acl_sqlite.ini', function (done) {
        this.plugin.load_relay_acl_sqlite_ini();
        assert.ok(this.plugin.cfg);
        done();
    });
});
