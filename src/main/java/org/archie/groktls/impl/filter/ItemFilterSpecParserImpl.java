/**
 * Copyright 2013 Tim Whittington
 *
 * Licensed under the The Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.archie.groktls.impl.filter;

import java.util.ArrayList;
import java.util.List;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.ItemFilterSpecParser;
import org.archie.groktls.NamedItem;
import org.archie.groktls.impl.filter.ItemFilterStep.Op;

public abstract class ItemFilterSpecParserImpl<I extends NamedItem, F extends Filter<I>> implements ItemFilterSpecParser<I> {

    protected abstract ItemFilterBuilderImpl<I> createFilterBuilder();

    @Override
    public final ItemFilter<I> parse(final String filterSpec) {
        final ItemFilterBuilderImpl<I> b = createFilterBuilder();

        final String[] parts = filterSpec.split("[:,]");
        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) {
                continue;
            }
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
        for (final String subpart : specParts) {
            final F filter = createFilter(subpart);
            if (filter == null) {
                throw new IllegalArgumentException(String.format("Could not understand spec part %s%s",
                                                                 subpart,
                                                                 (specParts.length == 1) ? "" : " of " + part));
            }
            filters.add(filter);
        }
        if (filters.isEmpty()) {
            throw new IllegalArgumentException(String.format("Could not understand spec part %s", part));
        }
        final F filter = (filters.size() == 1) ? filters.get(0) : combine(filters);
        b.step(op, filter);
    }

}
