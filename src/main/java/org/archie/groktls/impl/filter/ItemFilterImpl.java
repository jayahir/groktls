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
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.NamedItem;

public abstract class ItemFilterImpl<I extends NamedItem> implements ItemFilter<I> {

    public static class FilterResultImpl<I extends NamedItem> implements FilterResult<I> {

        public Set<I> included = new LinkedHashSet<I>();
        public Set<I> excluded = new LinkedHashSet<I>();
        public Set<I> blacklisted = new LinkedHashSet<I>();
        public Set<String> unparseable = new LinkedHashSet<String>();

        @Override
        public Set<I> getIncluded() {
            return Collections.unmodifiableSet(this.included);
        }

        @Override
        public String[] getIncludedNames() {
            final List<String> names = new ArrayList<String>();
            for (final I c : this.included) {
                names.add(c.getName());
            }
            return names.toArray(new String[names.size()]);
        }

        @Override
        public Set<I> getExcluded() {
            return Collections.unmodifiableSet(this.excluded);
        }

        @Override
        public Set<I> getBlacklisted() {
            return Collections.unmodifiableSet(this.blacklisted);
        }

        @Override
        public Set<String> getUnparseableNames() {
            return Collections.unmodifiableSet(this.unparseable);
        }

    }

    public interface Step<I extends NamedItem> {

        public void apply(FilterResultImpl<I> result, Set<I> supported, Set<I> defaults);
    }

    private final List<Step<I>> steps = new ArrayList<Step<I>>();

    public ItemFilterImpl(final List<Step<I>> steps) {
        this.steps.addAll(steps);
    }

    @Override
    public FilterResult<I> filter(final List<String> supportedItems, final List<String> defaultItems) {
        final FilterResultImpl<I> result = new FilterResultImpl<I>();

        final Set<I> supported = new LinkedHashSet<I>();
        final Set<I> defaults = new LinkedHashSet<I>();

        parse(supportedItems, supported, result.unparseable);
        parse(defaultItems, defaults, result.unparseable);

        for (final Step<I> step : this.steps) {
            step.apply(result, supported, defaults);
        }
        return result;
    }

    protected abstract void parse(List<String> items, Set<I> parsed, Set<String> unparseable);

    @Override
    public FilterResult<I> filter(final String[] supportedCiphers, final String[] defaultCiphers) {
        return filter(Arrays.asList(supportedCiphers), Arrays.asList(defaultCiphers));
    }

    @Override
    public FilterResult<I> filter(final SSLContext context) {
        return filter(getItems(context.getSupportedSSLParameters()), getItems(context.getDefaultSSLParameters()));
    }

    @Override
    public FilterResult<I> filterServer(final SSLContext context) {
        SSLEngine engine = context.createSSLEngine();
        return filter(getDefaults(engine), getSupported(engine));
    }

    protected abstract String[] getDefaults(SSLEngine engine);

    protected abstract String[] getSupported(SSLEngine engine);

    protected abstract String[] getItems(SSLParameters parameters);

}
