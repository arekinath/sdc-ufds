/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var sshpk = require('sshpk');
var ldap = require('ldapjs');

///--- API

module.exports = {

    add: function addKey(req, res, next) {
        var entry = req.toObject().attributes;
        var log = req.log;
        var key;
        var sdckey = false;

        log.debug({
            dn: req.dn.toString(),
            entry: entry
        }, 'Checking if we need to inject a PKCS attribute');

        var i;
        for (i = 0; i < (entry.objectclass || []).length; i++) {
            if (entry.objectclass[i].toLowerCase() === 'sdckey') {
                sdckey = true;
                break;
            }
        }
        if (!entry.openssh || entry.openssh.length === 0) {
            return next();
        }

        log.debug({
            dn: req.dn.toString(),
            entry: entry,
            sdckey: sdckey
        }, 'Inject?');

        if (!sdckey) {
            return next();
        }

        try {
            // Just in case, fix extra spaces in keys [CAPI-194]:
            key = entry.openssh[0].replace(/(\s){2,}/g, '$1').trim();

            key = sshpk.parseKey(key, 'ssh');

            // Delete the old pkcs attribute, in case it's a lie
            if (entry.pkcs)
                delete req.attributes[req.indexOf('pkcs')];
            req.addAttribute(new ldap.Attribute({
                type: 'pkcs',
                vals: [key.toString('pkcs8')]
            }));

            // If fingerprint is a lie though we have big problems
            var fp = key.fingerprint('md5').toString('hex');
            if (!entry.fingerprint || entry.fingerprint.length === 0) {
                req.addAttribute(new ldap.Attribute({
                    type: 'fingerprint',
                    vals: [fp]
                }));
            } else if (fp !== entry.fingerprint[0]) {
                throw new Error('Calculated fingerprint (' + fp + ') for ' +
                    'this key does not match the given one (' +
                    entry.fingerprint + ')');
            }

        } catch (e) {
            return next(new ldap.InvalidAttributeSyntaxError(e.toString()));
        }

        if (entry.attested)
            delete req.attributes[req.indexOf('attested')];

        if (entry.ykSerial)
            delete req.attributes[req.indexOf('ykSerial')];
        if (entry.ykPinRequired)
            delete req.attributes[req.indexOf('ykPinRequired')];
        if (entry.ykTouchRequired)
            delete req.attributes[req.indexOf('ykTouchRequired')];

        var attested = false;

        if (entry.attestation && entry.attestation.length > 0) {
            try {
                var chain = entry.attestation.map(function (pem) {
                    return (sshpk.parseCertificate(pem, 'pem'));
                });
            } catch (e) {
                return next(new ldap.InvalidAttributeSyntaxError(e.toString()));
            }

            for (i = 0; i < chain.length; ++i) {
                if (chain[i].isExpired()) {
                    return next(new ldap.InvalidAttributeSyntaxError(
                        'Attestation certificate ' + i + ' has expired'));
                }
                if (i > 0 && chain[i].purposes.indexOf('ca') === -1) {
                    return next(new ldap.InvalidAttributeSyntaxError(
                        'Attestation chain certificate ' + i + ' is not a CA'));
                }
            }
            for (i = 0; i < (chain.length - 1); ++i) {
                if (!chain[i].isSignedBy(chain[i + 1])) {
                    return next(new ldap.InvalidAttributeSyntaxError(
                        'Attestation certificate ' + i + ' not signed by next' +
                        ' in chain'));
                }
            }
            var last = chain[chain.length - 1];
            var ca = req.attestation_ca.find(function (maybeCA) {
                return (last.isSignedBy(maybeCA));
            });

            if (ca === undefined) {
                return next(new ldap.InvalidAttributeSyntaxError(
                    'Failed to find CA: ' + last.issuer.toString()));
            }

            attested = true;

            var der;

            var serialExt = chain[0].getExtension('1.3.6.1.4.1.41482.3.7');
            if (serialExt !== undefined) {
                der = new Ber.Reader(ext.data);
                req.addAttribute(new ldap.Attribute({
                    type: 'ykSerial',
                    vals: [der.readInteger()]
                }));
            }

            var policyExt = chain[0].getExtension('1.3.6.1.4.1.41482.3.8');
            if (policyExt !== undefined) {
                req.addAttribute(new ldap.Attribute({
                    type: 'ykPinRequired',
                    vals: [ext.data[0] > 1]
                }));
                req.addAttribute(new ldap.Attribute({
                    type: 'ykTouchRequired',
                    vals: [ext.data[1] > 1]
                }));
            }
        }

        req.addAttribute(new ldap.Atribute({
            type: 'attested',
            vals: [attested]
        }));

        return next();
    }

};
