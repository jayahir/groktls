package org.archie.groktls.impl.cipher;

import java.util.HashMap;
import java.util.Map;

import org.archie.groktls.cipher.KeyExchange;

public class KeyExchangeImpl implements KeyExchange {

    private static final Map<String,String> ALIASES = new HashMap<String, String>();
    
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

    public KeyExchangeImpl(String fullName, String keyAgreement, String authentication, boolean export, String exportVariant) {
        this.fullName = fullName;
        this.keyAgreement = dealias(keyAgreement);
        this.authentication = dealias(authentication);
        this.export = export;
        this.exportVariant = exportVariant;
    }

    public String getName() {
        return this.fullName;
    }

    public boolean isExport() {
        return this.export;
    }

    public String getExportVariant() {
        return this.exportVariant;
    }

    public String getKeyAgreementAlgo() {
        return this.keyAgreement;
    }

    public String getAuthenticationAlgo() {
        return this.authentication;
    }
    
    @Override
    public String toString() {
        return String.format("%s (%s,%s,%s,%s)", fullName, keyAgreement, authentication, export? "EXPORT" : "",  exportVariant != null ? exportVariant : "");
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((authentication == null) ? 0 : authentication.hashCode());
        result = prime * result + (export ? 1231 : 1237);
        result = prime * result + ((exportVariant == null) ? 0 : exportVariant.hashCode());
        result = prime * result + ((keyAgreement == null) ? 0 : keyAgreement.hashCode());
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
        KeyExchangeImpl other = (KeyExchangeImpl) obj;
        if (authentication == null) {
            if (other.authentication != null)
                return false;
        } else if (!authentication.equals(other.authentication))
            return false;
        if (export != other.export)
            return false;
        if (exportVariant == null) {
            if (other.exportVariant != null)
                return false;
        } else if (!exportVariant.equals(other.exportVariant))
            return false;
        if (keyAgreement == null) {
            if (other.keyAgreement != null)
                return false;
        } else if (!keyAgreement.equals(other.keyAgreement))
            return false;
        return true;
    }
    
    

}
