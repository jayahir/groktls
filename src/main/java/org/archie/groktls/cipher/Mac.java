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
 * The message authentication parameters of a {@link CipherSuite}.
 */
public interface Mac {

    /**
     * Obtains the un-normalised name of the cipher, including keylength and mode, as it appears in the cipher suite (e.g.
     * <code>SHA256</code>.
     */
    public String getName();

    /**
     * Obtains the canonical name of the base algorithm used in the message authentication.<br>
     * This is the normalised form of the name used in the full cipher suite name (e.g. the underlying hash where <code>HMAC</code> is used,
     * or the MAC algorithm if something other than <code>HMAC</code> is used).
     */
    public String getAlgorithm();

    /**
     * Obtains the size of the message authentication code produced by this algorithm, in bits.
     */
    public int getSize();

    @Override
    public boolean equals(Object o);

    @Override
    public int hashCode();

}
