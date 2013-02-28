package org.archie.groktls.impl.protocol.filter;

import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLParameters;

import org.archie.groktls.impl.filter.ItemFilterImpl;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;
import org.archie.groktls.protocol.ProtocolVariant;

public class ProtocolVariantFilterImpl extends ItemFilterImpl<ProtocolVariant> {

    private final ProtocolVariantParserImpl parser = new ProtocolVariantParserImpl();

    public ProtocolVariantFilterImpl(final List<org.archie.groktls.impl.filter.ItemFilterImpl.Step<ProtocolVariant>> steps) {
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

}
