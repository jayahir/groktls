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
        DEFAULT_KEYSIZES.put("CHACHA20_POLY1305", 256);
    }

    private static Map<String, Integer> STRENGTHS = new HashMap<String, Integer>();

    static {
        STRENGTHS.put("3DES_EDE", 112);
    }
    private static Map<String, CipherType> TYPES = new HashMap<String, CipherType>();

    static {
        TYPES.put("NULL", CipherType.UNKNOWN);
        TYPES.put("CBC", CipherType.BLOCK);
        TYPES.put("GCM", CipherType.AEAD);
        TYPES.put("CCM", CipherType.AEAD);
        TYPES.put("CCM_8", CipherType.AEAD);
        TYPES.put("CHACHA20_POLY1305", CipherType.AEAD);
        TYPES.put("CNT", CipherType.STREAM);
        TYPES.put("CTR", CipherType.STREAM);
        TYPES.put("RC4", CipherType.STREAM);
    }

    public static final CipherImpl CIPHER_NULL = new CipherImpl("NULL", "NULL", null, 0);

    public static final int DEFAULT = -1;

    private final CipherType type;

    private final String fullName;

    private final String algorithm;

    private final String mode;

    private final int keySize;

    private final int strength;

    public CipherImpl(final String fullName, final String algorithm, final String mode, final int keySize) {
        this.fullName = fullName;
        this.algorithm = dealias(algorithm);
        this.mode = dealias(mode);
        this.keySize = applyDefault(algorithm, keySize);
        this.strength = applyStrength(algorithm, this.keySize);
        this.type = identifyType(fullName, algorithm, mode);
    }

    private static CipherType identifyType(final String fullName, final String algorithm, final String mode) {
        if (TYPES.containsKey(fullName)) {
            return TYPES.get(fullName);
        }
        if (TYPES.containsKey(mode)) {
            return TYPES.get(mode);
        }
        if (TYPES.containsKey(algorithm)) {
            return TYPES.get(algorithm);
        }
        return CipherType.UNKNOWN;
    }

    private static int applyStrength(final String algo, final int keySize) {
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

    @Override
    public CipherType getType() {
        return this.type;
    }

    @Override
    public String getName() {
        return this.fullName;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getMode() {
        return this.mode;
    }

    @Override
    public int getKeySize() {
        return this.keySize;
    }

    @Override
    public int getStrength() {
        return this.strength;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = (prime * result) + ((this.algorithm == null) ? 0 : this.algorithm.hashCode());
        result = (prime * result) + this.keySize;
        result = (prime * result) + ((this.mode == null) ? 0 : this.mode.hashCode());
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
        final CipherImpl other = (CipherImpl) obj;
        if (this.algorithm == null) {
            if (other.algorithm != null) {
                return false;
            }
        } else if (!this.algorithm.equals(other.algorithm)) {
            return false;
        }
        if (this.keySize != other.keySize) {
            return false;
        }
        if (this.mode == null) {
            if (other.mode != null) {
                return false;
            }
        } else if (!this.mode.equals(other.mode)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return String.format("%s: (%s,%s,%s)", this.fullName, this.algorithm, this.mode, this.keySize);
    }

}
