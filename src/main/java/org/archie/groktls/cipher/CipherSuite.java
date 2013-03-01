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
