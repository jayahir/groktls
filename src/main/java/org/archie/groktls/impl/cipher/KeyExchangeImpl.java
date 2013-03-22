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

import org.archie.groktls.cipher.KeyExchange;

public class KeyExchangeImpl implements KeyExchange {

    private static final Map<String, String> ALIASES = new HashMap<String, String>();

    static {
        // GOST key exchange from http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
        ALIASES.put("GOSTR341094", "GOST94");
        ALIASES.put("GOSTR341001", "GOST2001");
        ALIASES.put("RSA_FIPS", "RSA");
        ALIASES.put("anon", "NULL");
    }

    static String dealias(final String algo) {
        if (ALIASES.containsKey(algo)) {
            return ALIASES.get(algo);
        }
        return algo;
    }

    private final boolean export;
    private final String authentication;
    private final String keyAgreement;
    private final String exportVariant;
    private final String fullName;

    public KeyExchangeImpl(final String fullName, final String keyAgreement, final String authentication, final boolean export,
            final String exportVariant) {
        this.fullName = fullName;
        this.keyAgreement = dealias(keyAgreement);
        this.authentication = dealias(authentication);
        this.export = export;
        this.exportVariant = exportVariant;
    }

    @Override
    public String getName() {
        return this.fullName;
    }

    @Override
    public boolean isExport() {
        return this.export;
    }

    @Override
    public String getExportVariant() {
        return this.exportVariant;
    }

    @Override
    public String getKeyAgreementAlgo() {
        return this.keyAgreement;
    }

    @Override
    public String getAuthenticationAlgo() {
        return this.authentication;
    }

    @Override
    public String toString() {
        return String.format("%s (%s,%s,%s,%s)",
                             this.fullName,
                             this.keyAgreement,
                             this.authentication,
                             this.export ? "EXPORT" : "",
                             this.exportVariant != null ? this.exportVariant : "");
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = (prime * result) + ((this.authentication == null) ? 0 : this.authentication.hashCode());
        result = (prime * result) + (this.export ? 1231 : 1237);
        result = (prime * result) + ((this.exportVariant == null) ? 0 : this.exportVariant.hashCode());
        result = (prime * result) + ((this.keyAgreement == null) ? 0 : this.keyAgreement.hashCode());
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
        final KeyExchangeImpl other = (KeyExchangeImpl) obj;
        if (this.authentication == null) {
            if (other.authentication != null) {
                return false;
            }
        } else if (!this.authentication.equals(other.authentication)) {
            return false;
        }
        if (this.export != other.export) {
            return false;
        }
        if (this.exportVariant == null) {
            if (other.exportVariant != null) {
                return false;
            }
        } else if (!this.exportVariant.equals(other.exportVariant)) {
            return false;
        }
        if (this.keyAgreement == null) {
            if (other.keyAgreement != null) {
                return false;
            }
        } else if (!this.keyAgreement.equals(other.keyAgreement)) {
            return false;
        }
        return true;
    }

}
