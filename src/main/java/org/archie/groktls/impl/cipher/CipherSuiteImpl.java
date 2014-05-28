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

import org.archie.groktls.cipher.Cipher;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.cipher.KeyExchange;
import org.archie.groktls.cipher.Mac;

class CipherSuiteImpl implements CipherSuite {

    private final KeyExchange keyExchange;
    private final CipherImpl cipher;
    private final MacImpl mac;
    private final String name;
    private final String normalisedName;
    private final boolean signalling;

    public CipherSuiteImpl(final String name, final KeyExchangeImpl keyExchange, final CipherImpl cipher, final MacImpl mac) {
        this.name = name;
        this.normalisedName = normalise(name);
        this.keyExchange = keyExchange;
        this.cipher = cipher;
        this.mac = mac;
        this.signalling = false;
    }

    private static String normalise(final String name) {
        if (name.startsWith("SSL_")) {
            return "TLS_" + name.substring("SSL_".length());
        }
        return name;
    }

    public CipherSuiteImpl(final String signallingCipherSuite) {
        this.name = signallingCipherSuite;
        this.normalisedName = signallingCipherSuite;
        this.keyExchange = null;
        this.cipher = null;
        this.mac = null;
        this.signalling = true;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public boolean isSignalling() {
        return this.signalling;
    }

    @Override
    public KeyExchange getKeyExchange() {
        return this.keyExchange;
    }

    @Override
    public Cipher getCipher() {
        return this.cipher;
    }

    @Override
    public Mac getMac() {
        return this.mac;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = (prime * result) + ((this.normalisedName == null) ? 0 : this.normalisedName.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CipherSuiteImpl other = (CipherSuiteImpl) obj;
        if (this.normalisedName == null) {
            if (other.normalisedName != null) {
                return false;
            }
        } else if (!this.normalisedName.equalsIgnoreCase(other.normalisedName)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return this.name;
    }

}
