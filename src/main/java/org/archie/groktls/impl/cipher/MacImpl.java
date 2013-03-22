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

    private final String fullName;
    private final String algorithm;
    private final int size;

    public MacImpl(final String fullName, final String algorithm) {
        this.fullName = fullName;
        this.algorithm = dealias(algorithm);
        this.size = detectSize(algorithm);
    }

    private static int detectSize(final String algorithm) {
        if (HASH_SIZES.containsKey(algorithm)) {
            return HASH_SIZES.get(algorithm);
        }
        return -1;
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
    public int getSize() {
        return this.size;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = (prime * result) + ((this.algorithm == null) ? 0 : this.algorithm.hashCode());
        result = (prime * result) + this.size;
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
        final MacImpl other = (MacImpl) obj;
        if (this.algorithm == null) {
            if (other.algorithm != null) {
                return false;
            }
        } else if (!this.algorithm.equals(other.algorithm)) {
            return false;
        }
        if (this.size != other.size) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return String.format("%s: (%s,%s)", this.fullName, this.algorithm, this.size);
    }

}
