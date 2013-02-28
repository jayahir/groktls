package org.archie.groktls.impl.protocol.filter;

import static org.archie.groktls.protocol.ProtocolVariantFilters.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.archie.groktls.impl.filter.ItemFilterBuilderImpl;
import org.archie.groktls.impl.filter.ItemFilterSpecParserImpl;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;
import org.archie.groktls.protocol.ProtocolVariant;
import org.archie.groktls.protocol.ProtocolVariantFilters.ProtocolVariantFilter;

public class ProtocolVariantFilterSpecParserImpl extends ItemFilterSpecParserImpl<ProtocolVariant, ProtocolVariantFilter> {

    private static final Map<String, ProtocolVariantFilter> VARIANT_STRINGS = new HashMap<String, ProtocolVariantFilter>();

    static {

        VARIANT_STRINGS.put("SUPPORTED", supportedIncludingUnsafe());

        VARIANT_STRINGS.put("ALL", all());
        VARIANT_STRINGS.put("COMPLEMENTOFALL", complementOfAll());
        VARIANT_STRINGS.put("UNSAFE", complementOfAll());
        VARIANT_STRINGS.put("DEFAULT", defaults());
        VARIANT_STRINGS.put("COMPLEMENTOFDEFAULT", complementOfDefaults());
        VARIANT_STRINGS.put("PSEUDO", pseudoProtocols());
    }

    private final ProtocolVariantParserImpl parser = new ProtocolVariantParserImpl();

    @Override
    protected ItemFilterBuilderImpl<ProtocolVariant> createFilterBuilder() {
        return new ProtocolVariantFilterBuilderImpl();
    }

    @Override
    protected boolean customApply(final String part, final ItemFilterBuilderImpl<ProtocolVariant> b) {
        return false;
    }

    @Override
    protected ProtocolVariantFilter combine(final List<ProtocolVariantFilter> filters) {
        return and(filters.toArray(new ProtocolVariantFilter[filters.size()]));
    }

    @Override
    protected ProtocolVariantFilter createFilter(final String part) {
        ProtocolVariantFilter filter = VARIANT_STRINGS.get(part);
        if (filter != null) {
            return filter;
        }
        if (part.startsWith("f")) {
            final String algo = part.substring(1);
            filter = family(algo);
        } else if (part.startsWith(">=")) {
            final String variant = part.substring(2);
            filter = minimumVersion(variant);
        } else {
            final ProtocolVariant pv = this.parser.parse(part);
            if (pv != null) {
                filter = protocolVariant(pv.getName());
            }
        }
        return filter;
    }

}
