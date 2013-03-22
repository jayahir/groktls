/**
 * Copyright 2013 Tim Whittington
 *
 * Licensed under the The Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.archie.groktls.impl.cipher;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.archie.groktls.ItemParser;
import org.archie.groktls.cipher.CipherSuite;

public class CipherSuiteParserImpl implements ItemParser<CipherSuite> {

    private static final String SSLv2_EXPORT40 = "_EXPORT40";
    private static final char SEPARATOR = '_';
    // Special case: SRP (RFC 5054) suites double-bang the key agreement
    // http://www.ietf.org/rfc/rfc5054.txt
    // Special case: Mozilla FIPS cipher suites
    // http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
    private static final Pattern PATTERN_DUAL_KEY_EXCHANGE = Pattern.compile("(RSA_FIPS|SRP_SHA|[^_]+)_([^_]+)(_EXPORT.*)?");
    private static final Pattern PATTERN_SINGLE_KEY_EXCHANGE = Pattern.compile("(RSA_FIPS|SRP_SHA|[^_]+)(_EXPORT.*)?");

    private static final String PREFIX_SSLV2 = "SSL_CK_";
    private static final String PREFIX_SSL = "SSL_";
    private static final String PREFIX_TLS = "TLS_";
    private static final String WITH = "_WITH_";
    private static final String SCSV_SUFFIX = "_SCSV";

    @Override
    public CipherSuite parse(final String cipherSuite) {
        if (cipherSuite == null) {
            throw new IllegalArgumentException("Cipher suite must be provided");
        }

        if (cipherSuite.endsWith(SCSV_SUFFIX)) {
            return new CipherSuiteImpl(cipherSuite);
        }
        final String cs = patchSSLv2(cipherSuite);
        final int withSplit = cs.indexOf(WITH);
        if (withSplit == -1) {
            return null;
        }

        final String keyExchangeSpec = removeTlsPrefix(cs.substring(0, withSplit));
        // TODO: Handle invalid prefix (result + error flag?)

        final KeyExchangeImpl keyExchange = parseKeyEchange(keyExchangeSpec);
        if (keyExchange == null) {
            return null;
        }

        final String cipherHash = cs.substring(withSplit + WITH.length());

        final int lastSep = cipherHash.lastIndexOf(SEPARATOR);
        if (lastSep == -1) {
            return null;
        }
        final String cipherSpec = cipherHash.substring(0, lastSep);
        final String hashSpec = cipherHash.substring(lastSep + 1);

        final CipherImpl cipher = parseCipher(cipherSpec);
        if (cipher == null) {
            return null;
        }

        final MacImpl hash = parseHash(hashSpec);
        if (hash == null) {
            return null;
        }
        return new CipherSuiteImpl(cipherSuite, keyExchange, cipher, hash);
    }

    @Override
    public Set<CipherSuite> parse(final Collection<String> ciphers) {
        final Set<CipherSuite> parsed = new LinkedHashSet<CipherSuite>();
        for (final String cipherSuite : ciphers) {
            final CipherSuite cs = parse(cipherSuite);
            if (cs != null) {
                parsed.add(cs);
            }
            // TODO: What to do with unparseable...
        }
        return parsed;
    }

    private MacImpl parseHash(final String hashSpec) {
        return new MacImpl(hashSpec, hashSpec);
    }

    private CipherImpl parseCipher(final String cipherSpec) {
        if (CipherImpl.CIPHER_NULL.getAlgorithm().equals(cipherSpec)) {
            return CipherImpl.CIPHER_NULL;
        }
        final CipherImpl cipher = parseAlgoSizeCipher(cipherSpec);

        return cipher;
    }

    private CipherImpl parseAlgoSizeCipher(final String cipherSpec) {
        final Matcher withKeysize = Pattern.compile("(3DES_EDE|[^_]+)(_[0-9]+)?(_[^_0-9]+)?(_[0-9]+)?").matcher(cipherSpec);
        if (withKeysize.matches()) {
            final String algo = withKeysize.group(1);
            String mode = withKeysize.group(3);
            if (mode != null) {
                mode = mode.substring(1);
            }
            String keysizeStr = withKeysize.group(2);
            if (keysizeStr == null) {
                keysizeStr = withKeysize.group(4);
            }
            if (keysizeStr != null) {
                try {
                    keysizeStr = keysizeStr.substring(1);
                    final int keySize = Integer.parseInt(keysizeStr);
                    return new CipherImpl(cipherSpec, algo, mode, keySize);
                } catch (final NumberFormatException e) {
                }
            }
            return new CipherImpl(cipherSpec, algo, mode, CipherImpl.DEFAULT);
        }
        return null;
    }

    private KeyExchangeImpl parseKeyEchange(final String keyExchangeSpec) {
        KeyExchangeImpl keyExchange = parseSingleAlgorithm(keyExchangeSpec);
        if (keyExchange == null) {
            keyExchange = parseDualAlgorithm(keyExchangeSpec);
        }
        return keyExchange;
    }

    private String patchSSLv2(final String cipherSuite) {
        if (!cipherSuite.startsWith(PREFIX_SSLV2)) {
            return cipherSuite;
        }

        String cs = cipherSuite.replace(SSLv2_EXPORT40, "");
        cs = cs.replace("_WITH", "");
        cs = cs.replace(PREFIX_SSLV2, "SSL_RSA_WITH_");
        // Correct algo + blocksize -> algo + default keysize
        cs = cs.replace("DES_64", "DES");
        cs = cs.replace("DES_192_EDE3", "3DES_EDE");
        // Remove EXPORT40 marker (which cripples the amount of the session key that is encrypted, not the algorithm).
        cs = cs.replace(SSLv2_EXPORT40, "");

        return cs;
    }

    private KeyExchangeImpl parseDualAlgorithm(final String algos) {
        final Matcher dual = PATTERN_DUAL_KEY_EXCHANGE.matcher(algos);
        if (dual.matches()) {
            final String baseExch = dual.group(1);
            final String baseAuth = dual.group(2);
            final String export = dual.group(3);
            final boolean exported = (export != null) && (export.length() > 0);
            final String exportVariant;
            if (exported) {
                final String variant = export.substring("EXPORT".length() + 1);
                exportVariant = (variant.length() == 0) ? null : variant;
            } else {
                exportVariant = null;
            }

            final KeyExchangeImpl keyExchange = new KeyExchangeImpl(algos, baseExch, baseAuth, exported, exportVariant);
            // System.err.println(keyExchange);
            return keyExchange;
        }
        return null;
    }

    private KeyExchangeImpl parseSingleAlgorithm(final String algos) {
        final Matcher single = PATTERN_SINGLE_KEY_EXCHANGE.matcher(algos);

        if (single.matches()) {
            final String baseAlg = single.group(1);
            final String export = single.group(2);
            final boolean exported = (export != null) && (export.length() > 0);
            final String exportVariant;
            if (exported) {
                final String variant = export.substring("EXPORT".length() + 1);
                exportVariant = (variant.length() == 0) ? null : variant;
            } else {
                exportVariant = null;
            }

            final KeyExchangeImpl keyExchange = new KeyExchangeImpl(algos, baseAlg, baseAlg, exported, exportVariant);
            // System.err.println(keyExchange);
            return keyExchange;
        }
        return null;
    }

    private String removeTlsPrefix(final String keyAgreement) {
        if (keyAgreement.startsWith(PREFIX_SSL)) {
            return keyAgreement.substring(PREFIX_SSL.length());
        }
        if (keyAgreement.startsWith(PREFIX_TLS)) {
            return keyAgreement.substring(PREFIX_TLS.length());
        }
        return keyAgreement;
    }

}
