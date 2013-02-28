package org.archie.groktls.impl.protocol.filter;

import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.impl.filter.ItemFilterStep;
import org.archie.groktls.protocol.ProtocolVariant;
import org.archie.groktls.protocol.ProtocolVariantFilters;

public class ProtocolVariantFilterStep extends ItemFilterStep<ProtocolVariant> {

    protected ProtocolVariantFilterStep(final Op op, final Filter<ProtocolVariant> filter) {
        super(op, filter);
    }

    @Override
    protected boolean isSafe(final ProtocolVariant variant) {
        return ProtocolVariantFilters.isSafe(variant);
    }

}
