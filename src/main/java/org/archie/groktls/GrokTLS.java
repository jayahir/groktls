package org.archie.groktls;

import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.impl.cipher.CipherSuiteParserImpl;
import org.archie.groktls.impl.cipher.filter.CipherSuiteFilterBuilderImpl;
import org.archie.groktls.impl.cipher.filter.CipherSuiteFilterSpecParserImpl;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;
import org.archie.groktls.impl.protocol.filter.ProtocolVariantFilterBuilderImpl;
import org.archie.groktls.impl.protocol.filter.ProtocolVariantFilterSpecParserImpl;
import org.archie.groktls.protocol.ProtocolVariant;

/**
 * Root entrypoint to GrokTLS functions.
 */
public class GrokTLS {

    /**
     * Constructs a parser that can be used to parse TLS cipher suite names and provide information about their meaning.
     */
    public ItemParser<CipherSuite> createCipherSuiteParser() {
        return new CipherSuiteParserImpl();
    }

    /**
     * Constructs a builder for {@link CipherSuiteFilter}s to apply criteria based filters on a set of cipher suites.
     */
    public ItemFilterBuilder<CipherSuite> createCipherSuiteFilterBuilder() {
        return new CipherSuiteFilterBuilderImpl();
    }

    /**
     * Constructs a parser that produces {@link CipherSuiteFilter}s from OpenSSL like cipher suite specification strings.
     */
    public ItemFilterSpecParser<CipherSuite> createCipherSuiteFilterSpecParser() {
        return new CipherSuiteFilterSpecParserImpl();
    }

    public ItemParser<ProtocolVariant> createProtocolVariantParser() {
        return new ProtocolVariantParserImpl();
    }

    /**
     * Constructs a builder for {@link CipherSuiteFilter}s to apply criteria based filters on a set of cipher suites.
     */
    public ItemFilterBuilder<ProtocolVariant> createProtocolVariantFilterBuilder() {
        return new ProtocolVariantFilterBuilderImpl();
    }

    /**
     * Constructs a parser that produces {@link CipherSuiteFilter}s from OpenSSL like cipher suite specification strings.
     */
    public ItemFilterSpecParser<ProtocolVariant> createProtocolVariantFilterSpecParser() {
        return new ProtocolVariantFilterSpecParserImpl();
    }

}
