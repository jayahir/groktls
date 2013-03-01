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
