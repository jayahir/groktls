package org.archie.groktls.impl.cipher.filter;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.impl.filter.ItemFilterBuilderImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl.Step;
import org.archie.groktls.impl.filter.ItemFilterStep.Op;

public class CipherSuiteFilterBuilderImpl extends ItemFilterBuilderImpl<CipherSuite> {

    @Override
    public ItemFilter<CipherSuite> build() {
        return new CipherSuiteFilterImpl(getSteps());
    }

    @Override
    protected Step<CipherSuite> createStep(final Op op, final Filter<CipherSuite> filter) {
        return new CipherSuiteFilterStep(op, filter);
    }
}
