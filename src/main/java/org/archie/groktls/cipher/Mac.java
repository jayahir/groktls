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
