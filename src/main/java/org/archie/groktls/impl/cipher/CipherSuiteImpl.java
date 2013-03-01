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
    private final boolean signalling;

    public CipherSuiteImpl(final String name, final KeyExchangeImpl keyExchange, final CipherImpl cipher, final MacImpl mac) {
        this.name = name;
        this.keyExchange = keyExchange;
        this.cipher = cipher;
        this.mac = mac;
        this.signalling = false;
    }

    public CipherSuiteImpl(final String signallingCipherSuite) {
        this.name = signallingCipherSuite;
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
        result = (prime * result) + ((this.name == null) ? 0 : this.name.hashCode());
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
        if (this.name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!this.name.equals(other.name)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return this.name;
    }

}
