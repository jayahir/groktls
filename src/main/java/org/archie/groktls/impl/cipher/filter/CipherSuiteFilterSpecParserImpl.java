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
package org.archie.groktls.impl.cipher.filter;

import static org.archie.groktls.cipher.CipherSuiteFilters.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.archie.groktls.cipher.Cipher.CipherType;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.cipher.CipherSuiteFilters.CipherFilter;
import org.archie.groktls.impl.cipher.CipherSuiteParserImpl;
import org.archie.groktls.impl.filter.ItemFilterBuilderImpl;
import org.archie.groktls.impl.filter.ItemFilterSpecParserImpl;

public class CipherSuiteFilterSpecParserImpl extends ItemFilterSpecParserImpl<CipherSuite, CipherFilter> {

    private static final Map<String, CipherFilter> CIPHER_STRINGS = new HashMap<String, CipherFilter>();
    static {
        CIPHER_STRINGS.put("FIPS140", fips());
        CIPHER_STRINGS.put("FIPS", fips());
        CIPHER_STRINGS.put("SCSV", signalling());

        CIPHER_STRINGS.put("SUPPORTED", supportedIncludingUnsafe());

        // Aliases as per OpenSSL
        // http://www.openssl.org/docs/apps/ciphers.html#CIPHER_STRINGS

        CIPHER_STRINGS.put("ALL", all());
        CIPHER_STRINGS.put("COMPLEMENTOFALL", complementOfAll());
        CIPHER_STRINGS.put("UNSAFE", complementOfAll());
        CIPHER_STRINGS.put("DEFAULT", defaults());
        CIPHER_STRINGS.put("COMPLEMENTOFDEFAULT", complementOfDefaults());
        CIPHER_STRINGS.put("HIGH", high());
        CIPHER_STRINGS.put("MEDIUM", medium());
        CIPHER_STRINGS.put("LOW", low());
        CIPHER_STRINGS.put("EXP", export());
        CIPHER_STRINGS.put("EXPORT", export());

        // TODO: SUITEB128ONLY?
        CIPHER_STRINGS.put("SUITEB128", suiteb128());
        CIPHER_STRINGS.put("SUITEB192", suiteb192());

        CIPHER_STRINGS.put("AEAD", encryptionType(CipherType.AEAD));
        CIPHER_STRINGS.put("BLOCK", encryptionType(CipherType.BLOCK));
        CIPHER_STRINGS.put("STREAM", encryptionType(CipherType.STREAM));
    }

    private final CipherSuiteParserImpl cipherSuiteParser = new CipherSuiteParserImpl();

    public CipherSuiteFilterSpecParserImpl() {
    }

    @Override
    protected ItemFilterBuilderImpl<CipherSuite> createFilterBuilder() {
        return new CipherSuiteFilterBuilderImpl();
    }

    @Override
    protected boolean customApply(final String part, final ItemFilterBuilderImpl<CipherSuite> cb) {
        if ("@STRENGTH".equals(part.trim())) {
            cb.sort(byEncryptionStrength());
            return true;
        } else if ("@KEYLENGTH".equals(part.trim())) {
            cb.sort(byKeyLength());
            return true;
        }
        return false;
    }

    @Override
    protected CipherFilter combine(final List<CipherFilter> filters) {
        return and(filters.toArray(new CipherFilter[filters.size()]));
    }

    @Override
    protected CipherFilter createFilter(final String part) {
        CipherFilter filter = CIPHER_STRINGS.get(part);
        if (filter != null) {
            return filter;
        }

        if (part.startsWith("k")) {
            final String algo = part.substring(1);
            filter = keyExchange(algo);
        } else if (part.startsWith("a")) {
            final String algo = part.substring(1);
            filter = authentication(algo);
        } else if (part.startsWith("e")) {
            // Match e<ALGO><KEYLENGTH>_<MODE> with all combinations supported
            final Matcher matcher = Pattern.compile("e(RC4|[^0-9_]+)?(_)?([0-9]{2,})?(_)?([^0-9_]+)?").matcher(part);
            final List<CipherFilter> filters = new ArrayList<CipherFilter>(3);
            if (matcher.matches()) {
                final String algo = matcher.group(1);
                if ((algo != null) && (algo.length() > 0)) {
                    filters.add(encryption(algo));
                }
                final String keysizeStr = matcher.group(3);
                if ((keysizeStr != null) && (keysizeStr.length() > 0)) {
                    try {
                        final int keysize = Integer.parseInt(keysizeStr);
                        filters.add(encryptionKeySize(keysize));
                    } catch (final NumberFormatException e) {
                        throw new IllegalArgumentException(String.format("Could not understand encryption algorithm spec %s", part));
                    }
                }
                final String mode = matcher.group(5);
                if ((mode != null) && (mode.length() > 0)) {
                    filters.add(encryptionMode(mode));
                }

            }
            if (filters.isEmpty()) {
                throw new IllegalArgumentException(String.format("Could not understand encryption algorithm spec %s", part));
            }
            filter = (filters.size() == 0) ? filters.get(0) : and(filters.toArray(new CipherFilter[filters.size()]));
        } else if (part.startsWith("m") || part.startsWith("h")) {
            final String algo = part.substring(1);
            filter = mac(algo);
        } else {
            final CipherSuite cs = this.cipherSuiteParser.parse(part);
            if (cs != null) {
                filter = cipherSuite(cs.getName());
            }
        }
        return filter;
    }
}
