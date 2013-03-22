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

import org.archie.groktls.NamedItem;

/**
 * The parsed form of an SSL/TLS cipher suite.
 */
public interface CipherSuite extends NamedItem {

    /**
     * Checks whether this cipher suite is a Signalling Cipher Suite Value (or SCSV). <br>
     * If <code>true</code>, then all other fields will be <code>null</code>.
     */
    public boolean isSignalling();

    /**
     * Obtains the key exchange algorithms used in the cipher suite.
     */
    public KeyExchange getKeyExchange();

    /**
     * Obtains the cipher algorithms used for confidentiality in the cipher suite.
     */
    public Cipher getCipher();

    /**
     * Obtains the message authentication algorithms used in the cipher suite.
     */
    public Mac getMac();

    @Override
    public boolean equals(Object obj);

    @Override
    public int hashCode();

}
