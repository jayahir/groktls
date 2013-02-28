package org.archie.groktls.impl.cipher;

import org.archie.groktls.cipher.Cipher;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.cipher.KeyExchange;
import org.archie.groktls.cipher.Mac;

class CipherSuiteImpl implements CipherSuite {

    private final KeyExchange keyExchange;
    private CipherImpl cipher;
    private MacImpl mac;
    private String name;
    private final boolean signalling;

    public CipherSuiteImpl(String name, KeyExchangeImpl keyExchange, CipherImpl cipher, MacImpl mac) {
        this.name = name;
        this.keyExchange = keyExchange;
        this.cipher = cipher;
        this.mac = mac;
        this.signalling = false;
    }

    public CipherSuiteImpl(String signallingCipherSuite) {
        this.name = signallingCipherSuite;
        this.keyExchange = null;
        this.cipher = null;
        this.mac = null;
        this.signalling = true;
    }

    public String getName() {
        return name;
    }
    
    public boolean isSignalling() {
        return signalling;
    }
    
    public KeyExchange getKeyExchange() {
        return keyExchange;
    }

    public Cipher getCipher() {
        return cipher;
    }

    public Mac getMac() {
        return mac;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CipherSuiteImpl other = (CipherSuiteImpl) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return name;
    }
    
}

