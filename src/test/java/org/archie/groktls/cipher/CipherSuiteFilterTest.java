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

import static org.archie.groktls.cipher.CipherSuiteFilters.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.archie.groktls.AbstractItemFilterTest;
import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilter.FilterResult;
import org.archie.groktls.ItemFilterSpecParser;
import org.archie.groktls.cipher.Cipher.CipherType;
import org.archie.groktls.impl.cipher.filter.CipherSuiteFilterBuilderImpl;
import org.archie.groktls.impl.cipher.filter.CipherSuiteFilterSpecParserImpl;
import org.junit.Before;
import org.junit.Test;

public class CipherSuiteFilterTest extends AbstractItemFilterTest<CipherSuite> {

    @Before
    public void setup() {
    }

    @Override
    protected ItemFilterSpecParser<CipherSuite> createSpecParser() {
        return new CipherSuiteFilterSpecParserImpl();
    }

    @Test
    public void testUnparseable() {
        List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "COMPLETE_RUBBISH");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).build();

        FilterResult<CipherSuite> result = filter.filter(supported, Collections.<String> emptyList());

        assertEquals(1, result.getIncluded().size());
        assertEquals(1, result.getUnparseableNames().size());
        assertTrue(result.getUnparseableNames().contains("COMPLETE_RUBBISH"));
    }

    // UNSAFE+LOW

    @Test
    public void testCiphersuite() {
        List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(cipherSuite("TLS_DHE_DSS_WITH_AES_128_CBC_SHA")).build();
        checkResult("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", filter, supported, expectedCiphers);
    }

    @Test
    public void testSupported() {
        List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                               "TLS_DHE_DSS_WITH_NULL_SHA",
                                               "TLS_NULL_WITH_AES_128_CBC_SHA",
                                               "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                               "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = supported;
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(supportedIncludingUnsafe()).build();
        checkResult("SUPPORTED", filter, supported, expectedCiphers);
    }

    @Test
    public void testSupportedPlusAuthentication() {
        List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                               "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                               "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                               "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                                               "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                                           "SSL_DHE_DSS_WITH_DES_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(supportedIncludingUnsafe(), authentication("DSS")))
                .build();
        checkResult("SUPPORTED+aDSS", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionKeysize() {
        List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                               "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                               "TLS_DH_anon_WITH_AES_256_CBC_SHA",
                                               "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
                                               "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                                               "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                                           "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
                                                           "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryptionKeySize(128)).build();
        checkResult("e128", filter, supported, expectedCiphers);
        checkResult("e_128", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionAlgo() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                                     "TLS_DH_anon_WITH_AES_256_CBC_SHA",
                                                     "TLS_DH_DSS_WITH_SEED_256_CBC_SHA",
                                                     "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryption("AES")).build();
        checkResult("eAES", filter, supported, expectedCiphers);
        checkResult("eAES_", filter, supported, expectedCiphers);
        checkResult("eAES__", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionAlgoRC4() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_RC4_128_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_127_SHA256",
                                                     "TLS_DH_anon_WITH_RC4_256_SHA",
                                                     "TLS_DH_DSS_WITH_SEED_256_CBC_SHA",
                                                     "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_RC4_128_SHA", "TLS_DHE_DSS_WITH_RC4_127_SHA256");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryption("RC4")).build();
        checkResult("eRC4", filter, supported, expectedCiphers);
        checkResult("eRC4_", filter, supported, expectedCiphers);
        checkResult("eRC4__", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionMode() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_GCM_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_GCM_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_GCM_SHA", "TLS_DHE_DSS_WITH_SEED_128_GCM_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryptionMode("GCM")).build();
        // eGCM would be interpreted as an algo
        checkResult("e_GCM", filter, supported, expectedCiphers);
        checkResult("e__GCM", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionAlgoAndKeysize() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_GCM_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_GCM_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(encryptionKeySize(128), encryption("AES"))).build();
        checkResult("eAES128", filter, supported, expectedCiphers);
        checkResult("eAES_128", filter, supported, expectedCiphers);
        checkResult("eAES_128_", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionAlgoAndMode() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_GCM_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_GCM_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_256_GCM_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(encryptionMode("GCM"), encryption("AES"))).build();
        checkResult("eAES_GCM", filter, supported, expectedCiphers);
        checkResult("eAES__GCM", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionKeysizeAndMode() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_GCM_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_GCM_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_GCM_SHA", "TLS_DHE_DSS_WITH_SEED_256_GCM_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(encryptionKeySize(128), encryptionMode("GCM"))).build();
        checkResult("e128_GCM", filter, supported, expectedCiphers);
        checkResult("e_128_GCM", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionAlgoKeysizeAndMode() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_GCM_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_GCM_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_GCM_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(encryption("AES"),
                                                                              encryptionKeySize(128),
                                                                              encryptionMode("GCM"))).build();
        checkResult("eAES128_GCM", filter, supported, expectedCiphers);
        checkResult("eAES_128_GCM", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionTypeAEAD() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CCM_SHA",
                                                     "TLS_DHE_DSS_WITH_CHACHA20_POLY1305_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CTR_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_CNT_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                           "TLS_DHE_DSS_WITH_AES_128_CCM_SHA",
                                                           "TLS_DHE_DSS_WITH_CHACHA20_POLY1305_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryptionType(CipherType.AEAD)).build();
        checkResult("AEAD", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionTypeBLOCK() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CCM_SHA",
                                                     "TLS_DH_anon_WITH_CHACHA20_POLY1305_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CTR_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_CNT_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryptionType(CipherType.BLOCK)).build();
        checkResult("BLOCK", filter, supported, expectedCiphers);
    }

    @Test
    public void testEncryptionTypeSTREAM() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_GCM_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CCM_SHA",
                                                     "TLS_DH_anon_WITH_CHACHA20_POLY1305_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CTR_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_CNT_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_RC4_SHA",
                                                           "TLS_DHE_DSS_WITH_SEED_128_CTR_SHA",
                                                           "TLS_DHE_DSS_WITH_SEED_256_CNT_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(encryptionType(CipherType.STREAM)).build();
        checkResult("STREAM", filter, supported, expectedCiphers);
    }

    @Test
    public void testAuthentication() {
        final List<String> supported = Arrays.asList("TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_DSS_WITH_AES_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(authentication("RSA")).build();
        checkResult("aRSA", filter, supported, expectedCiphers);
    }

    @Test
    public void testKeyExchange() {
        final List<String> supported = Arrays.asList("TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_DSS_WITH_AES_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_DSS_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(keyExchange("DH")).build();
        checkResult("kDH", filter, supported, expectedCiphers);
    }

    @Test
    public void testMac() {
        final List<String> supported = Arrays.asList("TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_128_CBC_MD5",
                                                     "TLS_RSA_WITH_AES_128_CBC_SHA256");
        final List<String> expectedCiphers = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(mac("SHA")).build();
        checkResult("mSHA", filter, supported, expectedCiphers);
        checkResult("hSHA", filter, supported, expectedCiphers);
    }

    @Test
    public void testAll() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_NULL_SHA",
                                                     "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).build();
        checkResult("ALL", filter, supported, expectedCiphers);
    }

    @Test
    public void testAllPlusAuthentication() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_NULL_SHA",
                                                     "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).build();
        checkResult("ALL+aDSS", filter, supported, expectedCiphers);
    }

    @Test
    public void testComplementOfAll() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_NULL_SHA",
                                                     "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_NULL_SHA",
                                                           "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                           "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(complementOfAll()).build();
        checkResult("COMPLEMENTOFALL", filter, supported, expectedCiphers);
        checkResult("UNSAFE", filter, supported, expectedCiphers);
    }

    @Test
    public void testDefaults() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_NULL_SHA",
                                                     "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> defaults = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                    "TLS_DHE_DSS_WITH_NULL_SHA",
                                                    "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                    "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(defaults()).build();
        checkResult("DEFAULT", filter, supported, expectedCiphers, defaults);
    }

    @Test
    public void testComplementOfDefaults() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_NULL_SHA",
                                                     "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> defaults = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                    "TLS_DHE_DSS_WITH_NULL_SHA",
                                                    "TLS_NULL_WITH_AES_128_CBC_SHA",
                                                    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                    "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(complementOfDefaults()).build();
        checkResult("COMPLEMENTOFDEFAULT", filter, supported, expectedCiphers, defaults);
    }

    @Test
    public void testHigh() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_127_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_128_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_127_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_SEED_256_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(high()).build();
        checkResult("HIGH", filter, supported, expectedCiphers);
    }

    @Test
    public void testMedium() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_127_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_128_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_127_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "TLS_DH_anon_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_RC4_128_SHA", "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(medium()).build();
        checkResult("MEDIUM", filter, supported, expectedCiphers);
    }

    @Test
    public void testLow() {
        final List<String> supported = Arrays.asList("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_127_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_RC4_128_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_127_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_256_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "TLS_DH_anon_WITH_SEED_128_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_SEED_128_CBC_NULL");
        final List<String> expectedCiphers = Arrays.asList("TLS_DHE_DSS_WITH_AES_127_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_SEED_127_CBC_SHA",
                                                           "TLS_DHE_DSS_WITH_DES_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(low()).build();
        checkResult("LOW", filter, supported, expectedCiphers);
    }

    @Test
    public void testExport() {
        final List<String> supported = Arrays.asList("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList();
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(export()).build();
        checkResult("EXPORT", filter, supported, expectedCiphers);
        checkResult("EXP", filter, supported, expectedCiphers);
    }

    @Test
    public void testUnsafeAndExport() {
        final List<String> supported = Arrays.asList("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
                                                     "TLS_DHE_DSS_WITH_DES_CBC_SHA",
                                                     "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(supportedIncludingUnsafe(), export())).build();
        checkResult("UNSAFE+EXPORT", filter, supported, expectedCiphers);
        checkResult("UNSAFE+EXP", filter, supported, expectedCiphers);
    }

    @Test
    public void testSortByStrength() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_127_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_DES_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_256_CBC_SHA",
                                                     "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_RSA_WITH_AES_256_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_127_CBC_SHA",
                                                           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                                           "TLS_RSA_WITH_DES_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).sort(byEncryptionStrength()).build();
        checkResult("ALL:@STRENGTH", filter, supported, expectedCiphers);
    }

    @Test
    public void testSortByLength() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_127_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_DES_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_256_CBC_SHA",
                                                     "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_RSA_WITH_AES_256_CBC_SHA",
                                                           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_127_CBC_SHA",
                                                           "TLS_RSA_WITH_DES_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).sort(byKeyLength()).build();
        checkResult("ALL:@KEYLENGTH", filter, supported, expectedCiphers);
    }

    @Test
    public void testCompositeTerm() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(and(encryption("AES"), keyExchange("DH")))
                .sort(byKeyLength())
                .build();
        checkResult("eAES+kDH", filter, supported, expectedCiphers);
    }

    @Test
    public void testDelete() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_RC4_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).delete(encryption("AES")).sort(byKeyLength())
                .build();
        checkResult("ALL:-eAES", filter, supported, expectedCiphers);
    }

    @Test
    public void testBlacklist() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_RC4_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> blacklist = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).blacklist(encryption("AES")).sort(byKeyLength())
                .build();
        checkResult("ALL:!eAES", filter, supported, expectedCiphers, Collections.<String> emptyList(), blacklist);
    }

    @Test
    public void testIncludeAfterDelete() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_SEED_128_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).delete(encryption("AES")).add(encryption("AES"))
                .sort(byKeyLength()).build();
        checkResult("ALL:-eAES:eAES", filter, supported, expectedCiphers);
    }

    @Test
    public void testMoveToEndAfterDelete() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_SEED_128_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        final List<String> blacklist = Collections.<String> emptyList();
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).delete(encryption("AES")).end(encryption("AES"))
                .sort(byKeyLength()).build();
        checkResult("ALL:-eAES:+eAES", filter, supported, expectedCiphers, blacklist);
    }

    @Test
    public void testIncludeAfterBlacklist() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_RSA_WITH_SEED_128_CBC_SHA");
        final List<String> blacklist = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).blacklist(encryption("AES")).add(encryption("AES"))
                .sort(byKeyLength()).build();
        checkResult("ALL:!eAES:eAES", filter, supported, expectedCiphers, Collections.<String> emptyList(), blacklist);
    }

    @Test
    public void testMoveToEndAfterBlacklist() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA");
        final List<String> blacklist = Arrays.asList("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).blacklist(keyExchange("DH")).end(encryption("AES"))
                .sort(byKeyLength()).build();
        checkResult("ALL:!kDH:+eAES", filter, supported, expectedCiphers, Collections.<String> emptyList(), blacklist);
    }

    @Test
    public void testMoveToEnd() {
        final List<String> supported = Arrays.asList("TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(all()).delete(keyExchange("DH")).end(encryption("AES"))
                .sort(byKeyLength()).build();
        checkResult("ALL:-kDH:+eAES", filter, supported, expectedCiphers);
    }

    @Test
    public void testRemoveUnsafe() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_NULL_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_DH_anon_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(complementOfAll()).delete(encryption("NULL")).build();
        checkResult("UNSAFE:-eNULL", filter, supported, expectedCiphers);
    }

    @Test
    public void testSpacesInFilterSpec() {
        final List<String> supported = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                                                     "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                                                     "TLS_RSA_WITH_NULL_SHA");
        final List<String> expectedCiphers = Arrays.asList("TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
        ItemFilter<CipherSuite> filter = new CipherSuiteFilterBuilderImpl().add(cipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA")).add(cipherSuite("TLS_DH_RSA_WITH_AES_128_CBC_SHA")).build();
        checkResult("TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DH_RSA_WITH_AES_128_CBC_SHA", filter, supported, expectedCiphers);
    }
}
