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
 * The key exchange algorithm parameters of a {@link CipherSuite}.
 */
public interface KeyExchange {

    /**
     * Obtains the un-normalised name of the key exchange parts of the overall cipher suite name. <br>
     * e.g. <code>DHE_RSA</code>
     */
    public String getName();

    /**
     * Checks whether this key exchange algorithm has export limitations.
     *
     * @return <code>true</code> iff the key exchange has export limits.
     */
    public boolean isExport();

    /**
     * Obtains any addtional information included in the export variant for this key exchange, e.g. <code>RSA_EXPORT1024</code> would return
     * <code>true</code> for {@link #isExport()} and <code>1024</code> as the export variant.
     */
    public String getExportVariant();

    /**
     * Obtains the normalised name of the key agreement part of the key exchange algorithm (e.g. <code>DH, ECDH, RSA</code>).
     * <p>
     * If there is no key exchange algorithm in the cipher suite, then this will be the string <code>NULL</code>.
     */
    public String getKeyAgreementAlgo();

    /**
     * Obtains the normalised name of the key authentication part of the key exchange algorithm (e.g. <code>DSS, RSA</code>).
     * <p>
     * If there is no key exchange algorithm in the cipher suite, or it specifies anonymous (<code>anon</code>) authentication, then this
     * will be the string <code>NULL</code>.
     */
    public String getAuthenticationAlgo();

    @Override
    public boolean equals(Object o);

    @Override
    public int hashCode();

}
