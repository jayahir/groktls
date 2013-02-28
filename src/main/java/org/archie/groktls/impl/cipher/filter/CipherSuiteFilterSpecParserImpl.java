package org.archie.groktls.impl.cipher.filter;

import static org.archie.groktls.cipher.CipherSuiteFilters.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

        CIPHER_STRINGS.put("NULL", and(supportedIncludingUnsafe(), encryption("NULL")));
        // aNULL, eNULL covered with spec syntax
        // kRSA, aRSA covered with spec syntax
        CIPHER_STRINGS.put("RSA", or(keyExchange("RSA"), authentication("RSA")));
        CIPHER_STRINGS.put("kEDH", keyExchange("DHE"));

        // TODO: kDH includes ephemeral?
        CIPHER_STRINGS.put("kDHr", and(keyExchange("DH"), authentication("RSA")));
        CIPHER_STRINGS.put("kDHd", and(keyExchange("DH"), authentication("DSS")));
        CIPHER_STRINGS.put("kDH", and(keyExchange("DH"), or(authentication("DSS"), authentication("RSA"))));

        // aDSS covered by spec syntax
        CIPHER_STRINGS.put("DSS", authentication("DSS"));

        // TODO: What is aDH?

        // Skipped kFZA, aFZA, eFZA, FZA (unimplemented by OpenSSL)

        // TODO: TLSv1.2, TLSv1, SSLv3, SSLv2

        // TODO: Does DH cover ECDH/ECDHE?
        CIPHER_STRINGS.put("DH", or(keyExchange("DH"), keyExchange("DHE")));
        CIPHER_STRINGS.put("ADH", and(supportedIncludingUnsafe(), or(keyExchange("DH"), keyExchange("DHE")), authentication("NULL")));

        CIPHER_STRINGS.put("AES128", and(encryption("AES"), encryptionKeySize(128)));
        CIPHER_STRINGS.put("AES256", and(encryption("AES"), encryptionKeySize(256)));
        CIPHER_STRINGS.put("AES", encryption("AES"));
        CIPHER_STRINGS.put("AESGCM", and(encryption("AES"), encryptionMode("GCM")));

        CIPHER_STRINGS.put("CAMELLIA128", and(encryption("CAMELLIA"), encryptionKeySize(128)));
        CIPHER_STRINGS.put("CAMELLIA256", and(encryption("CAMELLIA"), encryptionKeySize(256)));
        CIPHER_STRINGS.put("CAMELLIA", encryption("CAMELLIA"));

        CIPHER_STRINGS.put("3DES", encryption("3DES"));
        CIPHER_STRINGS.put("DES", encryption("DES"));
        CIPHER_STRINGS.put("RC4", encryption("RC4"));
        CIPHER_STRINGS.put("RC2", encryption("RC2"));
        CIPHER_STRINGS.put("IDEA", encryption("IDEA"));
        CIPHER_STRINGS.put("SEED", encryption("SEED"));
        CIPHER_STRINGS.put("MD5", encryption("MD5"));
        CIPHER_STRINGS.put("SHA1", mac("SHA"));
        CIPHER_STRINGS.put("SHA", mac("SHA"));
        CIPHER_STRINGS.put("SHA256", mac("SHA256"));
        CIPHER_STRINGS.put("SHA384", mac("SHA384"));

        // TODO: GOST
        // TODO: PSK
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
                    } catch (NumberFormatException e) {
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
