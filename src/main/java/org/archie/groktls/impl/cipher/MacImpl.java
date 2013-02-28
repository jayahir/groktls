package org.archie.groktls.impl.cipher;

import java.util.HashMap;
import java.util.Map;

import org.archie.groktls.cipher.Mac;

public class MacImpl implements Mac {

    private static final Map<String, String> ALIASES = new HashMap<String, String>();

    static {
        // GOST hash from
        // http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
        ALIASES.put("IMIT", "GOST89");
        ALIASES.put("GOSTR3411", "GOST94");
    }

    static String dealias(final String algo) {
        if (ALIASES.containsKey(algo)) {
            return ALIASES.get(algo);
        }
        return algo;
    }

    private static Map<String, Integer> HASH_SIZES = new HashMap<String, Integer>();

    static {
        HASH_SIZES.put("IMIT", 256); // TODO: This might be wrong
        HASH_SIZES.put("GOSTR3411", 256);
        HASH_SIZES.put("MD5", 128);
        HASH_SIZES.put("SHA", 160);
        HASH_SIZES.put("SHA256", 256);
        HASH_SIZES.put("SHA384", 384);
    }

    private String fullName;
    private String algorithm;
    private int size;

    public MacImpl(final String fullName, final String algorithm) {
        this.fullName = fullName;
        this.algorithm = dealias(algorithm);
        this.size = detectSize(algorithm);
    }

    private static int detectSize(String algorithm) {
        if (HASH_SIZES.containsKey(algorithm)) {
            return HASH_SIZES.get(algorithm);
        }
        return -1;
    }

    public String getName() {
        return fullName;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getSize() {
        return size;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + size;
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
        MacImpl other = (MacImpl) obj;
        if (algorithm == null) {
            if (other.algorithm != null)
                return false;
        } else if (!algorithm.equals(other.algorithm))
            return false;
        if (size != other.size)
            return false;
        return true;
    }
    
    @Override
    public String toString() {
        return String.format("%s: (%s,%s)", fullName, algorithm, size);
    }

}
