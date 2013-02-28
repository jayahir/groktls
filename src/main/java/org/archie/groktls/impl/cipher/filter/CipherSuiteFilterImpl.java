package org.archie.groktls.impl.cipher.filter;

import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLParameters;

import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.impl.cipher.CipherSuiteParserImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl;

public class CipherSuiteFilterImpl extends ItemFilterImpl<CipherSuite> {

    private final CipherSuiteParserImpl parser = new CipherSuiteParserImpl();

    public CipherSuiteFilterImpl(final List<Step<CipherSuite>> steps) {
        super(steps);
    }

    @Override
    protected Set<CipherSuite> parse(final List<String> items) {
        return this.parser.parse(items);
    }

    @Override
    protected String[] getItems(final SSLParameters parameters) {
        return parameters.getCipherSuites();
    }

}
