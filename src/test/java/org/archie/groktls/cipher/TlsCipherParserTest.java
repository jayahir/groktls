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

import static org.junit.Assert.*;

import org.archie.groktls.ItemParser;
import org.archie.groktls.cipher.Cipher.CipherType;
import org.archie.groktls.impl.cipher.CipherSuiteParserImpl;
import org.junit.Test;

public class TlsCipherParserTest {

    @Test
    public void testMalformedCipher() {
        final String cipherSuite = "TLS_DHE_DSS_WITH_RC4_128__SHA";
        ItemParser<CipherSuite> parser = new CipherSuiteParserImpl();
        CipherSuite suite = parser.parse(cipherSuite);

        assertNull(suite);
    }

    @Test
    public void testMozillaFipsCipherSuites() {
        // http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
        check("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_RSA_FIPS_WITH_DES_CBC_SHA", "RSA", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
    }

    @Test
    public void testSSlv3CipherSuites() {
        check("SSL_RSA_WITH_NULL_MD5", "RSA", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "MD5", 128);
        check("SSL_RSA_WITH_NULL_SHA", "RSA", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("SSL_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", true, null, "RC4", null, CipherType.STREAM, 40, "MD5", 128);
        check("SSL_RSA_WITH_RC4_128_MD5", "RSA", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        check("SSL_RSA_WITH_RC4_128_SHA", "RSA", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RSA", "RSA", true, null, "RC2", "CBC", CipherType.BLOCK, 40, "MD5", 128);
        check("SSL_RSA_WITH_IDEA_CBC_SHA", "RSA", "RSA", false, null, "IDEA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA", "RSA", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("SSL_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("SSL_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "DH", "DSS", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("SSL_DH_DSS_WITH_DES_CBC_SHA", "DH", "DSS", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA", "DH", "DSS", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "DH", "RSA", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("SSL_DH_RSA_WITH_DES_CBC_SHA", "DH", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA", "DH", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "DHE", "DSS", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("SSL_DHE_DSS_WITH_DES_CBC_SHA", "DHE", "DSS", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "DHE", "DSS", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DHE", "RSA", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("SSL_DHE_RSA_WITH_DES_CBC_SHA", "DHE", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", "DH", "NULL", true, null, "RC4", null, CipherType.STREAM, 40, "MD5", 128);
        check("SSL_DH_anon_WITH_RC4_128_MD5", "DH", "NULL", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        check("SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "DH", "NULL", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("SSL_DH_anon_WITH_DES_CBC_SHA", "DH", "NULL", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", "DH", "NULL", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("SSL_FORTEZZA_KEA_WITH_NULL_SHA", "FORTEZZA", "KEA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA", "FORTEZZA", "KEA", false, null, "FORTEZZA", "CBC", CipherType.BLOCK, 80, "SHA", 160);
        check("SSL_FORTEZZA_KEA_WITH_RC4_128_SHA", "FORTEZZA", "KEA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
    }

    @Test
    public void testTLS10_RFC4346_RFC5469_CipherSuites() {
        check("TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "MD5", 128);
        check("TLS_RSA_WITH_NULL_SHA", "RSA", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", true, null, "RC4", null, CipherType.STREAM, 40, "MD5", 128);
        check("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        check("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RSA", "RSA", true, null, "RC2", "CBC", CipherType.BLOCK, 40, "MD5", 128);
        check("TLS_RSA_WITH_IDEA_CBC_SHA", "RSA", "RSA", false, null, "IDEA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA", "RSA", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "DH", "DSS", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_DH_DSS_WITH_DES_CBC_SHA", "DH", "DSS", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "DH", "DSS", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "DH", "RSA", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_DH_RSA_WITH_DES_CBC_SHA", "DH", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "DH", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "DHE", "DSS", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_DHE_DSS_WITH_DES_CBC_SHA", "DHE", "DSS", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "DHE", "DSS", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DHE", "RSA", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "DH", "NULL", true, null, "RC4", null, CipherType.STREAM, 40, "MD5", 128);
        check("TLS_DH_anon_WITH_RC4_128_MD5", "DH", "NULL", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        check("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "DH", "NULL", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_DH_anon_WITH_DES_CBC_SHA", "DH", "NULL", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "DH", "NULL", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
    }

    @Test
    public void test_RFC3268_AESCipherSuites() {
        check("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DH_DSS_WITH_AES_128_CBC_SHA", "DH", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_DSS_WITH_AES_256_CBC_SHA", "DH", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DH_RSA_WITH_AES_128_CBC_SHA", "DH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_RSA_WITH_AES_256_CBC_SHA", "DH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DH_anon_WITH_AES_128_CBC_SHA", "DH", "NULL", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_anon_WITH_AES_256_CBC_SHA", "DH", "NULL", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
    }

    @Test
    public void testRFC413_RFC5932_CameliaCipherSuites() {
        check("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "RSA", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "RSA", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "DH", "DSS", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "DH", "DSS", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "DH", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "DH", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "DHE", "DSS", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "DHE", "DSS", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "DHE", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "DHE", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "DH", "NULL", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "DH", "NULL", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA", 160);
    }

    @Test
    public void testSEED_RFC4162_CipherSuites() {
        check("TLS_RSA_WITH_SEED_CBC_SHA", "RSA", "RSA", false, null, "SEED", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_DSS_WITH_SEED_CBC_SHA", "DH", "DSS", false, null, "SEED", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_RSA_WITH_SEED_CBC_SHA", "DH", "RSA", false, null, "SEED", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_DSS_WITH_SEED_CBC_SHA", "DHE", "DSS", false, null, "SEED", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_RSA_WITH_SEED_CBC_SHA", "DHE", "RSA", false, null, "SEED", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DH_anon_WITH_SEED_CBC_SHA", "DH", "NULL", false, null, "SEED", "CBC", CipherType.BLOCK, 128, "SHA", 160);
    }

    @Test
    public void testAria_RFC6209_CipherSuites() {
        check("TLS_RSA_WITH_ARIA_128_CBC_SHA256", "RSA", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_RSA_WITH_ARIA_256_CBC_SHA384", "RSA", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "DH", "DSS", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "DH", "DSS", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "DH", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "DH", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "DHE", "DSS", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "DHE", "DSS", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "DHE", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "DHE", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "DH", "NULL", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "DH", "NULL", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "ECDHE", "ECDSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "ECDHE", "ECDSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "ECDH", "ECDSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "ECDH", "ECDSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "ECDHE", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "ECDHE", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "ECDH", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "ECDH", "RSA", false, null, "ARIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
    }

    @Test
    public void testGOSTCopherSuites() {
        check("TLS_GOSTR341094_WITH_28147_CNT_IMIT", "GOST94", "GOST94", false, null, "GOST89", "CTR", CipherType.STREAM, 256, "GOST89", 256);
        check("TLS_GOSTR341001_WITH_28147_CNT_IMIT", "GOST2001", "GOST2001", false, null, "GOST89", "CTR", CipherType.STREAM, 256, "GOST89", 256);
        check("TLS_GOSTR341094_WITH_NULL_GOSTR3411", "GOST94", "GOST94", false, null, "NULL", null, CipherType.UNKNOWN, 0, "GOST94", 256);
        check("TLS_GOSTR341001_WITH_NULL_GOSTR3411", "GOST2001", "GOST2001", false, null, "NULL", null, CipherType.UNKNOWN, 0, "GOST94", 256);
    }

    @Test
    public void testAdditionalExport1024CipherSuites() {
        // http:// tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
        check("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "RSA", "RSA", true, "1024", "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "RSA", "RSA", true, "1024", "RC4", null, CipherType.STREAM, 56, "SHA", 160);
        check("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", "DHE", "DSS", true, "1024", "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", "DHE", "DSS", true, "1024", "RC4", null, CipherType.STREAM, 56, "SHA", 160);
        check("TLS_DHE_DSS_WITH_RC4_128_SHA", "DHE", "DSS", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
    }

    @Test
    public void testEC_RFC4492_CipherSuites() {
        check("TLS_ECDH_RSA_WITH_NULL_SHA", "ECDH", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_ECDH_RSA_WITH_RC4_128_SHA", "ECDH", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "ECDH", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "ECDH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "ECDH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_ECDH_ECDSA_WITH_NULL_SHA", "ECDH", "ECDSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "ECDH", "ECDSA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDH", "ECDSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "ECDH", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "ECDH", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_ECDHE_RSA_WITH_NULL_SHA", "ECDHE", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_ECDHE_ECDSA_WITH_NULL_SHA", "ECDHE", "ECDSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "ECDSA", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "ECDSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_ECDH_anon_WITH_NULL_SHA", "ECDH", "NULL", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_ECDH_anon_WITH_RC4_128_SHA", "ECDH", "NULL", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "ECDH", "NULL", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ECDH", "NULL", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "ECDH", "NULL", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
    }

    @Test
    public void testTls12_RFC5246_RFC5288_RFC5289_CipherSuites() {
        check("TLS_RSA_WITH_NULL_SHA256", "RSA", "RSA", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA256", 256);
        check("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA256", 256);
        check("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "DH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "DH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA256", 256);
        check("TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "DH", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "DH", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "DH", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "DH", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA256", 256);
        check("TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "DH", "DSS", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "DH", "DSS", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA256", 256);
        check("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE", "DSS", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE", "DSS", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "ECDH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "ECDH", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDH", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "ECDH", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "ECDH", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "ECDH", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDH", "ECDSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH", "ECDSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DH_anon_WITH_AES_128_CBC_SHA256", "DH", "NULL", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DH_anon_WITH_AES_256_CBC_SHA256", "DH", "NULL", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA256", 256);
        check("TLS_DH_anon_WITH_AES_128_GCM_SHA256", "DH", "NULL", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DH_anon_WITH_AES_256_GCM_SHA384", "DH", "NULL", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
    }

    @Test
    public void test_Camellia_RFC6367_CipherSuites() {
        check("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "ECDHE", "ECDSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "ECDHE", "ECDSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "ECDH", "ECDSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "ECDH", "ECDSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "ECDHE", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "ECDHE", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "ECDH", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", "ECDH", "RSA", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "RSA", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "RSA", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "DHE", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", "DHE", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "DH", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "DH", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", "DHE", "DSS", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", "DHE", "DSS", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", "DH", "DSS", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", "DH", "DSS", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", "DH", "NULL", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", "DH", "NULL", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "ECDHE", "ECDSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "ECDHE", "ECDSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "ECDH", "ECDSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "ECDH", "ECDSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "ECDHE", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", "ECDHE", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "ECDH", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "ECDH", "RSA", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", "PSK", "PSK", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", "PSK", "PSK", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", "DHE", "PSK", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", "DHE", "PSK", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", "RSA", "PSK", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", "RSA", "PSK", false, null, "CAMELLIA", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", "PSK", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", "PSK", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "DHE", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "DHE", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", "RSA", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", "RSA", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "ECDHE", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "ECDHE", "PSK", false, null, "CAMELLIA", "CBC", CipherType.BLOCK, 256, "SHA384", 384);


    }

    @Test
    public void test_RSA_RFC6655_CipherSuites() {
        check("TLS_RSA_WITH_AES_128_CCM", "RSA", "RSA", false, null, "AES", "CCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_RSA_WITH_AES_256_CCM", "RSA", "RSA", false, null, "AES", "CCM", CipherType.AEAD, 256, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_128_CCM", "DHE", "RSA", false, null, "AES", "CCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_256_CCM", "DHE", "RSA", false, null, "AES", "CCM", CipherType.AEAD, 256, "SHA256", 256);
        check("TLS_RSA_WITH_AES_128_CCM_8", "RSA", "RSA", false, null, "AES", "CCM_8", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_RSA_WITH_AES_256_CCM_8", "RSA", "RSA", false, null, "AES", "CCM_8", CipherType.AEAD, 256, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_128_CCM_8", "DHE", "RSA", false, null, "AES", "CCM_8", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_RSA_WITH_AES_256_CCM_8", "DHE", "RSA", false, null, "AES", "CCM_8", CipherType.AEAD, 256, "SHA256", 256);
    }

    @Test
    public void test_PSK_RFC6655_CipherSuites() {
        check("TLS_PSK_WITH_AES_128_CCM", "PSK", "PSK", false, null, "AES", "CCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_PSK_WITH_AES_256_CCM", "PSK", "PSK", false, null, "AES", "CCM", CipherType.AEAD, 256, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_AES_128_CCM", "DHE", "PSK", false, null, "AES", "CCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_AES_256_CCM", "DHE", "PSK", false, null, "AES", "CCM", CipherType.AEAD, 256, "SHA256", 256);
        check("TLS_PSK_WITH_AES_128_CCM_8", "PSK", "PSK", false, null, "AES", "CCM_8", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_PSK_WITH_AES_256_CCM_8", "PSK", "PSK", false, null, "AES", "CCM_8", CipherType.AEAD, 256, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_AES_128_CCM_8", "DHE", "PSK", false, null, "AES", "CCM_8", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_AES_256_CCM_8", "DHE", "PSK", false, null, "AES", "CCM_8", CipherType.AEAD, 256, "SHA256", 256);
    }

    @Test
    public void testPSK_RFC4279_CipherSuites() {
        check("TLS_PSK_WITH_RC4_128_SHA", "PSK", "PSK", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_PSK_WITH_3DES_EDE_CBC_SHA", "PSK", "PSK", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_PSK_WITH_AES_128_CBC_SHA", "PSK", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_PSK_WITH_AES_256_CBC_SHA", "PSK", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_DHE_PSK_WITH_RC4_128_SHA", "DHE", "PSK", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "DHE", "PSK", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "DHE", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "DHE", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_RSA_PSK_WITH_RC4_128_SHA", "RSA", "PSK", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "RSA", "PSK", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "RSA", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "RSA", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
    }

    @Test
    public void testPSK_RFC4785_CipherSuites() {
        check("TLS_PSK_WITH_NULL_SHA", "PSK", "PSK", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_DHE_PSK_WITH_NULL_SHA", "DHE", "PSK", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_RSA_PSK_WITH_NULL_SHA", "RSA", "PSK", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
    }

    @Test
    public void testPSK_RFC5487_CipherSuites() {
        check("TLS_PSK_WITH_AES_128_GCM_SHA256", "PSK", "PSK", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_PSK_WITH_AES_256_GCM_SHA384", "PSK", "PSK", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "DHE", "PSK", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", "DHE", "PSK", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
        check("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "RSA", "PSK", false, null, "AES", "GCM", CipherType.AEAD, 128, "SHA256", 256);
        check("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "RSA", "PSK", false, null, "AES", "GCM", CipherType.AEAD, 256, "SHA384", 384);
    }

    @Test
    public void testPSK_RFC5489_CipherSuites() {
        check("TLS_ECDHE_PSK_WITH_RC4_128_SHA", "ECDHE", "PSK", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "ECDHE", "PSK", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "ECDHE", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "ECDHE", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "ECDHE", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA256", 256);
        check("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "ECDHE", "PSK", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA384", 384);
        check("TLS_ECDHE_PSK_WITH_NULL_SHA", "ECDHE", "PSK", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA", 160);
        check("TLS_ECDHE_PSK_WITH_NULL_SHA256", "ECDHE", "PSK", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA256", 256);
        check("TLS_ECDHE_PSK_WITH_NULL_SHA384", "ECDHE", "PSK", false, null, "NULL", null, CipherType.UNKNOWN, 0, "SHA384", 384);
    }

    @Test
    public void testSSv2CipherSuites() {
        check("SSL_CK_RC4_128_WITH_MD5", "RSA", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        // SSL_CK_RC4_128_EXPORT40_WITH_MD5 is 128 bit encryption with only 40 bits of session key in ciphertext
        check("SSL_CK_RC4_128_EXPORT40_WITH_MD5", "RSA", "RSA", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        check("SSL_CK_RC2_128_CBC_WITH_MD5", "RSA", "RSA", false, null, "RC2", "CBC", CipherType.BLOCK, 128, "MD5", 128);
        check("SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5", "RSA", "RSA", false, null, "RC2", "CBC", CipherType.BLOCK, 128, "MD5", 128);
        check("SSL_CK_IDEA_128_CBC_WITH_MD5", "RSA", "RSA", false, null, "IDEA", "CBC", CipherType.BLOCK, 128, "MD5", 128);
        check("SSL_CK_DES_64_CBC_WITH_MD5", "RSA", "RSA", false, null, "DES", "CBC", CipherType.BLOCK, 56, "MD5", 128);
        check("SSL_CK_DES_192_EDE3_CBC_WITH_MD5", "RSA", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "MD5", 128);
    }

    @Test
    public void testKerberos_RFC2712_CipherSuites() {
        check("TLS_KRB5_WITH_DES_CBC_SHA", "KRB5", "KRB5", false, null, "DES", "CBC", CipherType.BLOCK, 56, "SHA", 160);
        check("TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "KRB5", "KRB5", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_KRB5_WITH_RC4_128_SHA", "KRB5", "KRB5", false, null, "RC4", null, CipherType.STREAM, 128, "SHA", 160);
        check("TLS_KRB5_WITH_IDEA_CBC_SHA", "KRB5", "KRB5", false, null, "IDEA", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_KRB5_WITH_DES_CBC_MD5", "KRB5", "KRB5", false, null, "DES", "CBC", CipherType.BLOCK, 56, "MD5", 128);
        check("TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "KRB5", "KRB5", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "MD5", 128);
        check("TLS_KRB5_WITH_RC4_128_MD5", "KRB5", "KRB5", false, null, "RC4", null, CipherType.STREAM, 128, "MD5", 128);
        check("TLS_KRB5_WITH_IDEA_CBC_MD5", "KRB5", "KRB5", false, null, "IDEA", "CBC", CipherType.BLOCK, 128, "MD5", 128);
        check("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "KRB5", "KRB5", true, null, "DES", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "KRB5", "KRB5", true, null, "RC2", "CBC", CipherType.BLOCK, 40, "SHA", 160);
        check("TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "KRB5", "KRB5", true, null, "RC4", null, CipherType.STREAM, 40, "SHA", 160);
        check("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "KRB5", "KRB5", true, null, "DES", "CBC", CipherType.BLOCK, 40, "MD5", 128);
        check("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "KRB5", "KRB5", true, null, "RC2", "CBC", CipherType.BLOCK, 40, "MD5", 128);
        check("TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "KRB5", "KRB5", true, null, "RC4", null, CipherType.STREAM, 40, "MD5", 128);
    }

    @Test
    public void testEmptyRenegotiation_RFC5746_CipherSuites() {
        checkSCSV("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
    }

    @Test
    public void testSRP_RFC5054_CipherSuites() {
        check("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "SRP_SHA", "SRP_SHA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "SRP_SHA", "RSA", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "SRP_SHA", "DSS", false, null, "3DES", "CBC", CipherType.BLOCK, 168, "SHA", 160);
        check("TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "SRP_SHA", "SRP_SHA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "SRP_SHA", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "SRP_SHA", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 128, "SHA", 160);
        check("TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "SRP_SHA", "SRP_SHA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "SRP_SHA", "RSA", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
        check("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "SRP_SHA", "DSS", false, null, "AES", "CBC", CipherType.BLOCK, 256, "SHA", 160);
    }

    private void check(final String cipherSuite,
                       final String keyExchange,
                       final String authentication,
                       final boolean keyExchangeExport,
                       final String keyExchangeExportVariant,
                       final String encryptionAlgo,
                       final String encryptionMode,
                       final CipherType cipherType,
                       final int keySize,
                       final String hash,
                       final int hashSize) {
        ItemParser<CipherSuite> parser = new CipherSuiteParserImpl();

        CipherSuite suite = parser.parse(cipherSuite);
        assertNotNull(cipherSuite, suite);
        assertNotNull(cipherSuite, suite.getKeyExchange());
        assertNotNull(cipherSuite, suite.getCipher());
        assertNotNull(cipherSuite, suite.getMac());

        assertEquals(cipherSuite, cipherSuite, suite.getName());
        assertFalse(cipherSuite, suite.isSignalling());
        assertEquals(cipherSuite, keyExchange, suite.getKeyExchange().getKeyAgreementAlgo());
        assertEquals(cipherSuite, authentication, suite.getKeyExchange().getAuthenticationAlgo());
        assertEquals(cipherSuite, keyExchangeExport, suite.getKeyExchange().isExport());
        assertEquals(cipherSuite, keyExchangeExportVariant, suite.getKeyExchange().getExportVariant());

        assertEquals(cipherSuite, encryptionAlgo, suite.getCipher().getAlgorithm());
        assertEquals(cipherSuite, encryptionMode, suite.getCipher().getMode());
        assertEquals(cipherSuite, cipherType, suite.getCipher().getType());
        assertEquals(cipherSuite, keySize, suite.getCipher().getKeySize());
        assertEquals(cipherSuite, hash, suite.getMac().getAlgorithm());
        assertEquals(cipherSuite, hashSize, suite.getMac().getSize());
    }

    private void checkSCSV(final String cipherSuite) {
        ItemParser<CipherSuite> parser = new CipherSuiteParserImpl();

        CipherSuite suite = parser.parse(cipherSuite);
        assertNotNull(cipherSuite, suite);
        assertNull(cipherSuite, suite.getKeyExchange());
        assertNull(cipherSuite, suite.getCipher());
        assertNull(cipherSuite, suite.getMac());

        assertEquals(cipherSuite, cipherSuite, suite.getName());
        assertTrue(cipherSuite, suite.isSignalling());
    }

}
