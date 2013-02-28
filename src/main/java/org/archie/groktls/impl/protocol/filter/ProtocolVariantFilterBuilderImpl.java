package org.archie.groktls.impl.protocol.filter;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.impl.filter.ItemFilterBuilderImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl.Step;
import org.archie.groktls.impl.filter.ItemFilterStep.Op;
import org.archie.groktls.protocol.ProtocolVariant;

public class ProtocolVariantFilterBuilderImpl extends ItemFilterBuilderImpl<ProtocolVariant> {

    @Override
    public ItemFilter<ProtocolVariant> build() {
        return new ProtocolVariantFilterImpl(getSteps());
    }

    @Override
    protected Step<ProtocolVariant> createStep(final Op op, final Filter<ProtocolVariant> filter) {
        return new ProtocolVariantFilterStep(op, filter);
    }

}
