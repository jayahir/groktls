package org.archie.groktls.impl.cipher.filter;

import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.cipher.CipherSuiteFilters;
import org.archie.groktls.impl.filter.ItemFilterStep;

public class CipherSuiteFilterStep extends ItemFilterStep<CipherSuite> {

    protected CipherSuiteFilterStep(final Op op, final Filter<CipherSuite> filter) {
        super(op, filter);
    }

    @Override
    protected boolean isSafe(final CipherSuite cipher) {
        return CipherSuiteFilters.isSafe(cipher);
    }

}
