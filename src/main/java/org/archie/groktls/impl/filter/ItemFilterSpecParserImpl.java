package org.archie.groktls.impl.filter;

import java.util.ArrayList;
import java.util.List;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterSpecParser;
import org.archie.groktls.NamedItem;
import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.impl.filter.ItemFilterStep.Op;

public abstract class ItemFilterSpecParserImpl<I extends NamedItem, F extends Filter<I>> implements ItemFilterSpecParser<I> {

    protected abstract ItemFilterBuilderImpl<I> createFilterBuilder();

    @Override
    public final ItemFilter<I> parse(final String filterSpec) {
        ItemFilterBuilderImpl<I> b = createFilterBuilder();

        final String[] parts = filterSpec.split("[:,]");
        for (String part : parts) {
            apply(part, b);
        }

        return b.build();
    }

    protected abstract boolean customApply(final String part, final ItemFilterBuilderImpl<I> b);

    protected abstract F combine(List<F> filters);

    protected abstract F createFilter(String subpart);

    private void apply(final String part, final ItemFilterBuilderImpl<I> b) {
        final Op op;
        final String spec;

        if (customApply(part, b)) {
            return;
        }

        if (part.startsWith("+")) {
            op = Op.MOVE_TO_END;
            spec = part.substring(1);
        } else if (part.startsWith("-")) {
            op = Op.DELETE;
            spec = part.substring(1);
        } else if (part.startsWith("!")) {
            op = Op.BLACKLIST;
            spec = part.substring(1);
        } else {
            op = Op.ADD;
            spec = part;
        }

        final String[] specParts = spec.split("\\+");
        final List<F> filters = new ArrayList<F>(specParts.length);
        for (String subpart : specParts) {
            F filter = createFilter(subpart);
            if (filter == null) {
                throw new IllegalArgumentException(String.format("Could not understand ciphersuite spec part %s%s",
                                                                 subpart,
                                                                 (specParts.length == 1) ? "" : " of " + part));
            }
            filters.add(filter);
        }
        if (filters.isEmpty()) {
            throw new IllegalArgumentException(String.format("Could not understand ciphersuite spec part %s", part));
        }
        final F filter = (filters.size() == 1) ? filters.get(0) : combine(filters);
        b.step(op, filter);
    }

}
