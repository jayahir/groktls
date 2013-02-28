package org.archie.groktls.impl.cipher;

import java.util.HashMap;
import java.util.Map;

import org.archie.groktls.cipher.Cipher;

public class CipherImpl implements Cipher {

    private static final Map<String, String> ALIASES = new HashMap<String, String>();

    static {
        // GOST encryption from
        // http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
        ALIASES.put("DES40", "DES");
        ALIASES.put("28147", "GOST89");
        ALIASES.put("CNT", "CTR");
        ALIASES.put("3DES_EDE", "3DES");
    }

    static String dealias(final String algo) {
        if (ALIASES.containsKey(algo)) {
            return ALIASES.get(algo);
        }
        return algo;
    }

    private static Map<String, Integer> DEFAULT_KEYSIZES = new HashMap<String, Integer>();

    static {
        DEFAULT_KEYSIZES.put("3DES_EDE", 168);
        DEFAULT_KEYSIZES.put("3DES", 168);
        DEFAULT_KEYSIZES.put("DES40", 40);
        DEFAULT_KEYSIZES.put("DES", 56);
        DEFAULT_KEYSIZES.put("FORTEZZA", 80); // Skipjack
        DEFAULT_KEYSIZES.put("FORTEZZA", 80); // Skipjack
        DEFAULT_KEYSIZES.put("28147", 256); // GOST 89
        DEFAULT_KEYSIZES.put("IDEA", 128);
        DEFAULT_KEYSIZES.put("SEED", 128);
    }

    private static Map<String, Integer> STRENGTHS = new HashMap<String, Integer>();

    static {
        STRENGTHS.put("3DES_EDE", 112);
    }
    
    public static final CipherImpl CIPHER_NULL = new CipherImpl("NULL", "NULL", null, 0);

    public static final int DEFAULT = -1;

    private String fullName;

    private String algorithm;

    private String mode;

    private int keySize;

    private int strength;

    public CipherImpl(String fullName, String algorithm, final String mode, final int keySize) {
        this.fullName = fullName;
        this.algorithm = dealias(algorithm);
        this.mode = dealias(mode);
        this.keySize = applyDefault(algorithm, keySize);
        this.strength = applyStrength(algorithm, this.keySize);
    }

    private static int applyStrength(String algo, int keySize) {
        if (STRENGTHS.containsKey(algo)) {
            return STRENGTHS.get(algo);
        }
        return keySize;
    }

    private static int applyDefault(final String algo, final int keySize) {
        if (keySize != DEFAULT) {
            return keySize;
        }
        if (DEFAULT_KEYSIZES.containsKey(algo)) {
            return DEFAULT_KEYSIZES.get(algo);
        }
        return keySize;
    }

    public String getName() {
        return fullName;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getMode() {
        return mode;
    }

    public int getKeySize() {
        return keySize;
    }
    
    public int getStrength() {
        return strength;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + keySize;
        result = prime * result + ((mode == null) ? 0 : mode.hashCode());
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
        CipherImpl other = (CipherImpl) obj;
        if (algorithm == null) {
            if (other.algorithm != null)
                return false;
        } else if (!algorithm.equals(other.algorithm))
            return false;
        if (keySize != other.keySize)
            return false;
        if (mode == null) {
            if (other.mode != null)
                return false;
        } else if (!mode.equals(other.mode))
            return false;
        return true;
    }
    
    @Override
    public String toString() {
        return String.format("%s: (%s,%s,%s)", fullName, algorithm, mode, keySize);
    }

}
