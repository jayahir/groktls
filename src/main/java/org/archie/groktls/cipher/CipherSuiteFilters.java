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
package org.archie.groktls.cipher;

import java.util.Comparator;
import java.util.Set;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterBuilder;
import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.cipher.Cipher.CipherType;

/**
 * Common {@link Filter}s that can be applied in a {@link ItemFilterBuilder} to filter a set of {@link CipherSuite}s.
 * <p>
 * Unless noted, all filters imply that they will only include {@link #isSafe(CipherSuite) safe cipher suites} - i.e. unless the filter is
 * {@link #and(CipherFilter...) concatenated} with an unsafe filter, or is applied to already matched results that are unsafe, then unsafe
 * cipher suites will not be matched.
 * <p>
 * The filters provided here are generally the same as the equivalent operations in the <a
 * href="http://www.openssl.org/docs/apps/ciphers.html">OpenSSL ciphers</a> command, but differ particularly in the treatment of
 * <code>ALL</ALL>, which excludes all {@link #isSafe(CipherSuite) unsafe} cipher suites, unlike the OpenSSL version.
 */
public class CipherSuiteFilters {

    /**
     * A {@link Filter} for {@link CipherSuite}s.
     */
    public interface CipherFilter extends Filter<CipherSuite> {
    }

    /**
     * A filter that will by default only include unsafe cipher suites.
     */
    private abstract static class UnsafeFilter implements CipherFilter {
        @Override
        public boolean isSafe() {
            return false;
        }

    }

    /**
     * A filter that will by default only include safe cipher suites.
     */
    private abstract static class SafeFilter implements CipherFilter {
        @Override
        public boolean isSafe() {
            return true;
        }
    }

    /**
     * Comparison of {@link CipherSuite} by {@link Cipher#getKeySize() key size}.
     */
    private static final Comparator<? super CipherSuite> KEY_LENGTH_COMPARATOR = new Comparator<CipherSuite>() {

        @Override
        public int compare(final CipherSuite o1, final CipherSuite o2) {
            final Cipher c1 = o1.getCipher();
            final Cipher c2 = o2.getCipher();
            if (c1 == c2) {
                return 0;
            } else if (c2 == null) {
                return 1;
            } else if (c1 == null) {
                return -1;
            }
            return c2.getKeySize() - c1.getKeySize();
        }
    };

    /**
     * Comparison of {@link CipherSuite} by {@link Cipher#getStrength() encryption strength}.
     */
    private static final Comparator<? super CipherSuite> KEY_STRENGTH_COMPARATOR = new Comparator<CipherSuite>() {

        @Override
        public int compare(final CipherSuite o1, final CipherSuite o2) {
            final Cipher c1 = o1.getCipher();
            final Cipher c2 = o2.getCipher();
            if (c1 == c2) {
                return 0;
            } else if (c2 == null) {
                return 1;
            } else if (c1 == null) {
                return -1;
            }
            return c2.getStrength() - c1.getStrength();
        }
    };

    /**
     * Produces a comparator for {@link CipherSuite}s that will order them by {@link Cipher#getKeySize() key length}.
     * <p>
     * <em>Filter spec usage:</em> <code>@KEYLENGTH</code>.
     */
    public static Comparator<? super CipherSuite> byKeyLength() {
        return KEY_LENGTH_COMPARATOR;
    }

    /**
     * Produces a comparator for {@link CipherSuite}s that will order them by {@link Cipher#getStrength() encryption strength}.
     * <p>
     * <em>Filter spec usage:</em> <code>@STRENGTH</code>.
     */
    public static Comparator<? super CipherSuite> byEncryptionStrength() {
        return KEY_STRENGTH_COMPARATOR;
    }

    /**
     * Matches a single cipher suite by name. The provided cipher suite name is not parsed and is directly matched.
     * <p>
     * <em>Filter spec usage:</em> literal cipher suite name, e.g. <code>TLS_DH_RSA_WITH_AES_128_CBC_SHA</code>.
     *
     * @param cipherSuite the cipher suite name to match.
     */
    public static CipherFilter cipherSuite(final String cipherSuite) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return cipherSuite.equals(cipher.getName());
            }
        };
    }

    /**
     * Matches any signalling cipher suite (e.g. <code>TLS_EMPTY_RENEGOTIATION_INFO_SCSV</code>).
     * <p>
     * <em>Filter spec usage:</em> <code>SCSV</code>.
     */
    public static CipherFilter signalling() {
        return new UnsafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return cipher.isSignalling();
            }
        };
    }

    /**
     * Matches cipher suites that use a specified encryption (cipher) algorithm.
     * <p>
     * <em>Filter spec usage:</em> <code>eCIPHER</code>, e.g. <code>eAES</code>.
     *
     * @param algorithm the normalised name of the encryption algorithm (e.g. <code>AES, 3DES, RC4, NULL</code>).
     */
    public static CipherFilter encryption(final String algorithm) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return ((cipher.getCipher() != null) && algorithm.equals(cipher.getCipher().getAlgorithm()));
            }
        };
    }

    /**
     * Matches cipher suites that use a specifed encryption (cipher) mode.
     * <p>
     * <em>Filter spec usage:</em> <code>eCIPHER_MODE</code> or <code>e_MODE</code>, e.g. <code>eAES_GCM</code> or <code>e_GCM</code>.
     *
     * @param mode the name of the cipher mode to match (e.g. <code>CBC, GCM</code>).
     */
    public static CipherFilter encryptionMode(final String mode) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return ((cipher.getCipher() != null) && mode.equals(cipher.getCipher().getMode()));
            }
        };
    }

    /**
     * Matches cipher suites that use encryption (a cipher) with key lengths of a minimum size.
     * <p>
     * <em>Filter spec usage:</em> <code>eCIPHER_KEYLENGTH</code> or <code>e_KEYLENGTH</code>, e.g. <code>eAES_128</code> or
     * <code>e_128</code>.
     *
     * @param minSize the minimum number of bits in the cipher key length (e.g. <code>128</code>)
     */
    public static CipherFilter encryptionKeySize(final int minSize) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (cipher.getCipher() != null) && (cipher.getCipher().getKeySize() >= minSize);
            }
        };
    }

    /**
     * Matches cipher suites that use encryption (a cipher) with effective key strengths of a minimum size.
     * <p>
     * <em>Filter spec usage:</em> no equivalent.
     *
     * @param minSize the minimum number of bits in the cipher strength (e.g. <code>128</code>)
     */
    public static CipherFilter encryptionStrength(final int minSize) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (cipher.getCipher() != null) && (cipher.getCipher().getStrength() >= minSize);
            }
        };
    }

    /**
     * Matches cipher suites that use encryption (a cipher) of the specified type.
     * <p>
     * <em>Filter spec usage:</em> <code>AEAD</code> or <code>STREAM</code> or <code>BLOCK</code>.
     *
     * @param minSize the minimum number of bits in the cipher strength (e.g. <code>128</code>)
     */
    public static CipherFilter encryptionType(final CipherType type) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (cipher.getCipher() != null) && (cipher.getCipher().getType() == type);
            }
        };
    }

    /**
     * Matches cipher suites that use a specified authentication algorithm.
     * <p>
     * <em>Filter spec usage:</em> <code>aALGO</code>, e.g. <code>aRSA</code> or <code>aNULL</code>.
     *
     * @param algorithm the normalised name of the authentication algorithm (e.g. <code>DSS, RSA, NULL</code>).
     */
    public static CipherFilter authentication(final String algorithm) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (cipher.getKeyExchange() != null) && algorithm.equals(cipher.getKeyExchange().getAuthenticationAlgo());
            }
        };
    }

    /**
     * Matches cipher suites that use a specified key exchange algorithm.
     * <p>
     * <em>Filter spec usage:</em> <code>kALGO</code>, e.g. <code>kDHE</code> or <code>kNULL</code>.
     *
     * @param algorithm the normalised name of the key exchange algorithm (e.g. <code>RSA, DH, DHE, NULL</code>).
     */
    public static CipherFilter keyExchange(final String algorithm) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (cipher.getKeyExchange() != null) && algorithm.equals(cipher.getKeyExchange().getKeyAgreementAlgo());
            }
        };
    }

    /**
     * Matches cipher suites that use a specified MAC algorithm algorithm. <br>
     * The name matched against is the one used in the cipher suite name (e.g. the underlying hash where <code>HMAC</code> is used, or the
     * MAC algorithm if something other than <code>HMAC</code> is used).
     * <p>
     * <em>Filter spec usage:</em> <code>mALGO</code>, e.g. <code>mSHA</code> or <code>mNULL</code>.
     *
     * @param algorithm the normalised name of the MAC algorithm (e.g. <code>SHA, SHA256</code>).
     */
    public static CipherFilter mac(final String algorithm) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (cipher.getMac() != null) && algorithm.equals(cipher.getMac().getAlgorithm());
            }
        };
    }

    /**
     * Matches all of the {@link ItemFilter#filter(java.util.List, java.util.List) supported cipher suites}, with the exception of any
     * cipher suites that are considered {@link #isSafe(CipherSuite) unsafe} - these unsafe cipher suites can be matched using
     * {@link #complementOfAll()}.
     * <p>
     * <em>Filter spec usage:</em> <code>ALL</code>.
     * <p>
     * This differs from the OpenSSL <b>ALL</b> cipher suite in that it also excludes <code>NULL</code> key exchange and authentication
     * ciphers.
     */
    public static CipherFilter all() {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                // TODO: Note the non-equivalence to SAFE (i.e. in the context of SUPPORTED:-ALL)
                return true;
            }
        };
    }

    /**
     * Matches all of the {@link ItemFilter#filter(java.util.List, java.util.List) supported cipher suites}, <b>including</b> cipher suites
     * with <code>NULL</code> key exchange, authentication or encryption.
     * <p>
     * <em>Filter spec usage:</em> <code>SUPPORTED</code>.
     * <p>
     * <b>Unsafe:</b> this will match <b>unsafe</b> cipher suites.
     */
    public static CipherFilter supportedIncludingUnsafe() {
        return new UnsafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return true;
            }
        };
    }

    /**
     * Matches any supported ciphers that are not matched by {@link #all()}. <br>
     * This will include any of the <code>NULL</code> cipher suites excluded by {@link #all()}.
     * <p>
     * <em>Filter spec usage:</em> <code>COMPLEMENTOFALL</code> or <code>UNSAFE</code>.
     * <p>
     * <b>Unsafe:</b> this will match <b>unsafe</b> cipher suites.
     */
    public static CipherFilter complementOfAll() {
        return new UnsafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return !CipherSuiteFilters.isSafe(cipher);
            }
        };
    }

    /**
     * Determines if a cipher is considered safe by filter rules.
     * <p>
     * Currently a cipher suite is considered safe iff:
     * <ul>
     * <li>It does not use <code>NULL</code> {@link KeyExchange#getKeyAgreementAlgo() key agreement}.</li>
     * <li>It does not use <code>NULL</code> or <code>anon</code> {@link KeyExchange#getAuthenticationAlgo() authentication}.</li>
     * <li>It does not use <code>NULL</code> {@link CipherSuite#getCipher() encryption/cipher}</li>
     * <li>It does not use <code>EXPORT</code> grade {@link CipherSuite#getCipher() encryption/cipher}</li>
     * <li>It does not use the <code>MD5</code> {@link CipherSuite#getMac() digest algorithm}</li>
     * </ul>
     *
     * @param cipher the cipher suite to check.
     * @return <code>true</code> iff the cipher suite is safe to use.
     */
    public static boolean isSafe(final CipherSuite cipher) {
        // TODO: Move export to cipher?
        return cipher.isSignalling() || ((cipher.getKeyExchange() != null) && !cipher.getKeyExchange().isExport()
                                         && !cipher.getKeyExchange().getKeyAgreementAlgo().equals("NULL")
                                         && !cipher.getKeyExchange().getAuthenticationAlgo().equals("NULL")
                                         && !cipher.getCipher().getAlgorithm().equals("NULL")
                                         && (cipher.getMac() != null)
                                         && !cipher.getMac().getAlgorithm().equals("NULL") && !cipher.getMac().getAlgorithm().equals("MD5"));
    }

    /**
     * Matches any of the {@link ItemFilter#filter(java.util.List, java.util.List) default cipher suites} that are also matched by
     * {@link #all()}. <br>
     * This will not include any of the unsafe cipher suites excluded by {@link #all()}, even if they are specified as defaults during the
     * filter invocation.
     * <p>
     * <em>Filter spec usage:</em> <code>DEFAULT</code>.
     */
    public static CipherFilter defaults() {
        return isDefault(true);
    }

    private static CipherFilter isDefault(final boolean include) {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return (include == defaults.contains(cipher));
            }
        };
    }

    /**
     * Matches any of the cipher suites matched by {@link #all()} that are not in the {@link #defaults() defaults}. <br>
     * This will not include any of the unsafe cipher suites excluded by {@link #all()} - i.e. {@link #defaults() defaults} and
     * {@link #complementOfDefaults()} are subsets of the safe default cipher suites.
     * <p>
     * <em>Filter spec usage:</em> <code>COMPLEMENTOFDEFAULT</code>.
     */
    public static CipherFilter complementOfDefaults() {
        return isDefault(false);
    }

    /**
     * Matches cipher suites that use high key length encryption, which is currently defined as AES with 128 bit keys or other ciphers with
     * key lengths > 128 bit.
     * <p>
     * <em>Filter spec usage:</em> <code>HIGH</code>.
     */
    public static CipherFilter high() {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                if (cipher.getCipher() == null) {
                    return false;
                }
                final Cipher c = cipher.getCipher();
                return ((c.getKeySize() > 128) || ((c.getKeySize() == 128) && "AES".equals(c.getAlgorithm())));
            }
        };
    }

    /**
     * Matches cipher suites that use medium key length encryption, which is currently defined as algorithms other than AES using 128 bit
     * keys.
     * <p>
     * <em>Filter spec usage:</em> <code>MEDIUM</code>.
     */
    public static CipherFilter medium() {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                if (cipher.getCipher() == null) {
                    return false;
                }
                final Cipher c = cipher.getCipher();
                return (c.getKeySize() == 128) && !"AES".equals(c.getAlgorithm());
            }
        };
    }

    /**
     * Matches cipher suites that use low key length encryption, which is currently defined as any key length < 128 bits.
     * <p>
     * <em>Filter spec usage:</em> <code>LOW</code>.
     */
    public static CipherFilter low() {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                if (cipher.getCipher() == null) {
                    return false;
                }
                return !cipher.getKeyExchange().isExport() && !cipher.getCipher().getAlgorithm().equals("NULL")
                       && (cipher.getCipher().getKeySize() < 128);
            }
        };
    }

    /**
     * Matches any export cipher suites.
     * <p>
     * <b>Requires Unsafe:</b> export filters are not considered {@link #isSafe(CipherSuite) safe}, so this filter is only sensible when
     * combined with an unsafe filter.
     * <p>
     * <em>Filter spec usage:</em> <code>EXP</code> or <code>EXPORT</code>.
     */
    public static CipherFilter export() {
        return new SafeFilter() {
            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                // TODO: This relies on export marker on key exchange also
                // implying encryption export
                return (cipher.getKeyExchange() != null) && (cipher.getKeyExchange().isExport());
            }
        };
    }

    /**
     * Matches any cipher suites using algorithms approved (or generally accepted) for use in FIPS 140-2.
     * <p>
     * This is based on information in <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf">FIPS 140-2 Annex A</a>
     * and <a href="http://csrc.nist.gov/publications/nistpubs/800-52/SP800-52.pdf">NIST Special Publication 800-52</a>.
     * <p>
     * The current interpretation of this is:
     * <ul>
     * <li><b>Key exchange:</b> <code>DH, DHE, RSA, ECDH, ECDHE</code></li>
     * <li><b>Authentication:</b> <code>DSS, RSA, ECDSA<</code></li>
     * <li><b>Encryption:</b> <code>AES, 3DES</code></li>
     * <li><b>Encryption Mode:</b> <code>CBC, GCM, CCM</code></li>
     * <li><b>Mac/Hash:</b> <code>SHA, SHA256, SHA384</code></li>
     * </ul>
     * <p>
     * <em>Filter spec usage:</em> <code>FIPS</code> or <code>FIPS140</code>.
     */
    public static CipherFilter fips() {
        // http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf
        // http://csrc.nist.gov/publications/nistpubs/800-52/SP800-52.pdf
        return and(or(keyExchange("DH"), keyExchange("DHE"), keyExchange("RSA"), keyExchange("ECDH"), keyExchange("ECDHE")),
                   or(authentication("DSS"), authentication("RSA"), authentication("ECDSA")),
                   or(encryption("AES"), encryption("3DES")),
                   or(encryptionMode("CBC"), encryptionMode("GCM"), encryptionMode("CCM")),
                   or(mac("SHA"), mac("SHA256"), mac("SHA384"), mac("SHA512")));
    }

    /**
     * Matches any cipher suites using algorithms approved for use in TLS by NSA Suite B with a 128 bit minimum security.
     * <p>
     * This is based on information in <a href="http://tools.ietf.org/html/rfc6460#section-3.1">RFC 6460</a>.
     * <p>
     * The current interpretation of this is:
     * <ul>
     * <li><b>Key exchange:</b> <code>ECDHE</code></li>
     * <li><b>Authentication:</b> <code>ECDSA<</code></li>
     * <li><b>Encryption:</b> <code>AES</code></li>
     * <li><b>Encryption Mode:</b> <code>GCM</code></li>
     * <li><b>Mac/Hash:</b> <code>SHA256, SHA384</code></li>
     * </ul>
     * <p>
     * <em>Filter spec usage:</em> <code>SUITEB128</code>.
     */
    public static CipherFilter suiteb128() {
        // http://tools.ietf.org/html/rfc6460#section-3.1
        return and(keyExchange("ECDHE"),
                   authentication("ECDSA"),
                   encryption("AES"),
                   encryptionMode("GCM"),
                   or(mac("SHA256"), mac("SHA384"), mac("SHA512")));
    }

    /**
     * Matches any cipher suites using algorithms approved for use in TLS by NSA Suite B with a 192 bit minimum security.
     * <p>
     * This is based on information in <a href="http://tools.ietf.org/html/rfc6460#section-3.1">RFC 6460</a>.
     * <p>
     * The current interpretation of this is:
     * <ul>
     * <li><b>Key exchange:</b> <code>ECDHE</code></li>
     * <li><b>Authentication:</b> <code>ECDSA<</code></li>
     * <li><b>Encryption:</b> <code>AES with 256 bit key length</code></li>
     * <li><b>Encryption Mode:</b> <code>GCM</code></li>
     * <li><b>Mac/Hash:</b> <code>SHA384</code></li>
     * </ul>
     * <p>
     * <em>Filter spec usage:</em> <code>SUITEB192</code>.
     */
    public static CipherFilter suiteb192() {
        // http://tools.ietf.org/html/rfc6460#section-3.1
        // http://www.nsa.gov/ia/programs/suiteb_cryptography/
        //
        return and(keyExchange("ECDHE"),
                   authentication("ECDSA"),
                   encryption("AES"),
                   encryptionKeySize(256),
                   encryptionMode("GCM"),
                   or(mac("SHA384"), mac("SHA512")));
    }

    /**
     * Matches any cipher suites not matched by a specified filter.
     * <p>
     * <b>Safety:</b> the filter produced is safe iff the negated filter is safe.
     *
     * @param filter the filter to negate.
     */
    public static CipherFilter not(final CipherFilter filter) {
        return new CipherFilter() {
            @Override
            public boolean isSafe() {
                return filter.isSafe();
            }

            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                return !filter.matches(cipher, defaults);
            }
        };
    }

    /**
     * Matches any cipher suites matched by any of the specified filters.
     * <p>
     * <b>Safety:</b> the filter produced is safe iff the first filter combines is safe.
     */
    public static CipherFilter or(final CipherFilter... filters) {
        return new CipherFilter() {
            @Override
            public boolean isSafe() {
                return (filters.length > 0) && filters[0].isSafe();
            }

            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                for (final Filter<CipherSuite> filter : filters) {
                    if (filter.matches(cipher, defaults)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    /**
     * Matches any cipher suites matched by all of the specified filters.
     * <p>
     * <b>Safety:</b> the filter produced is safe iff the first filter combines is safe.
     */
    public static CipherFilter and(final CipherFilter... filters) {
        return new CipherFilter() {
            @Override
            public boolean isSafe() {
                return (filters.length > 0) && filters[0].isSafe();
            }

            @Override
            public boolean matches(final CipherSuite cipher, final Set<CipherSuite> defaults) {
                for (final Filter<CipherSuite> filter : filters) {
                    if (!filter.matches(cipher, defaults)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

}
