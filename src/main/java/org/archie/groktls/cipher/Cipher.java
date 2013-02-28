package org.archie.groktls.cipher;

public interface Cipher {

    String getName();

    String getAlgorithm();

    String getMode();

    int getKeySize();

    /**
     * Obtains the effective key length of the cipher, where that is known for the particular cipher. <br>
     * This is a best effort estimation based on known vulnerabilities in the cipher algorithm: e.g. the effective strength of 3 key
     * <code>3DES_EDE</code> with a 168 bit key length is 112 bits due to a meet in the middle attack.
     * 
     * @return the key strength of the cipher, which will be the {@link #getKeySize() key size} if there are no major known vulnerabilities.
     */
    int getStrength();

}
