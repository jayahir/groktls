package org.archie.groktls.impl.filter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.NamedItem;

public abstract class ItemFilterImpl<I extends NamedItem> implements ItemFilter<I> {

    public static class FilterResultImpl<I extends NamedItem> implements FilterResult<I> {

        public Set<I> included = new LinkedHashSet<I>();
        public Set<I> excluded = new LinkedHashSet<I>();
        public Set<I> blacklisted = new LinkedHashSet<I>();

        @Override
        public Set<I> getIncluded() {
            return Collections.unmodifiableSet(this.included);
        }

        @Override
        public String[] getIncludedNames() {
            List<String> names = new ArrayList<String>();
            for (I c : this.included) {
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
        Set<I> supported = parse(supportedItems);
        Set<I> defaults = parse(defaultItems);

        FilterResultImpl<I> result = new FilterResultImpl<I>();
        for (Step<I> step : this.steps) {
            step.apply(result, supported, defaults);
        }
        return result;
    }

    protected abstract Set<I> parse(List<String> items);

    @Override
    public FilterResult<I> filter(final String[] supportedCiphers, final String[] defaultCiphers) {
        return filter(Arrays.asList(supportedCiphers), Arrays.asList(defaultCiphers));
    }

    @Override
    public FilterResult<I> filter(final SSLContext context) {
        return filter(getItems(context.getSupportedSSLParameters()), getItems(context.getDefaultSSLParameters()));
    }

    protected abstract String[] getItems(SSLParameters parameters);

}
