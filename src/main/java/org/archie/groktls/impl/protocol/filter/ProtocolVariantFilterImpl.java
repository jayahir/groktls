package org.archie.groktls.impl.protocol.filter;

import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.archie.groktls.impl.filter.ItemFilterImpl;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;
import org.archie.groktls.protocol.ProtocolVariant;

public class ProtocolVariantFilterImpl extends ItemFilterImpl<ProtocolVariant> {

    private final ProtocolVariantParserImpl parser = new ProtocolVariantParserImpl();

    public ProtocolVariantFilterImpl(final List<Step<ProtocolVariant>> steps) {
        super(steps);
    }

    @Override
    protected String[] getItems(final SSLParameters parameters) {
        return parameters.getProtocols();
    }

    @Override
    protected Set<ProtocolVariant> parse(final List<String> items) {
        return this.parser.parse(items);
    }

    @Override
    protected String[] getDefaults(final SSLEngine engine) {
        return engine.getEnabledProtocols();
    }

    @Override
    protected String[] getSupported(final SSLEngine engine) {
        return engine.getSupportedProtocols();
    }
}
