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

/**
 * The cipher part of a {@link CipherSuite}, which provides the encryption or confidentiality of data transmitted.
 */
public interface Cipher {

    /**
     * Types of ciphers used in TLS cipher suites.
     */
    public enum CipherType {
        /** The type of the cipher is unknown */
        UNKNOWN,

        /** Block ciphers, e.g. DES, AES */
        BLOCK,

        /** Stream ciphers, e.g. RC4, Salsa20 */
        STREAM,

        /** AEAD ciphers or cipher modes, e.g. AES/GCM */
        AEAD
    }

    /**
     * Obtains the un-normalised name of the cipher, including keylength and mode, as it appears in the cipher suite (e.g.
     * <code>3DES_EDE_CBC</code> or <code>AES_256_GCM</code>.
     * <p>
     * If the cipher suite uses no encryption, then this will be the string <code>NULL</code>.
     */
    public String getName();

    /**
     * Obtains the canonical name of the cipher algorithm.<br/>
     * Some ciphers have different aliases in different TLS cipher suites (e.g. <code>3DES_EDE</code>) and this method will return a
     * normalised canonical form of the cipher name (e.g <code>3DES</code>).
     * <p>
     * If the cipher suite uses no encryption, then this will be the string <code>NULL</code>.
     */
    public String getAlgorithm();

    /**
     * Obtains the canonical name of the cipher mode (e.g. <code>CBC</code> or <code>GCM</code>).
     * <p>
     * If the cipher suite uses no encryption, then this will be <code>null</code>.
     */
    public String getMode();

    /**
     * Obtains the key length of the cipher in bits.
     * <p>
     * If the cipher suite uses no encryption, then this will be <code>0</code>.
     */
    public int getKeySize();

    /**
     * Obtains the effective key length of the cipher in bits, where that is known for the particular cipher. <br>
     * This is a best effort estimation based on known vulnerabilities in the cipher algorithm: e.g. the effective strength of 3 key
     * <code>3DES_EDE</code> with a 168 bit key length is 112 bits due to a meet in the middle attack.
     *
     * @return the key strength of the cipher, which will be the {@link #getKeySize() key size} if there are no major known vulnerabilities.
     */
    public int getStrength();

    /**
     * Obtains the type of this cipher.
     *
     * @return the type of cipher used in the cipher suite.
     */
    public CipherType getType();

}
