package org.archie.groktls;

import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;

/**
 * A filter that can be applied to a set of input items (e.g. items or protocol variants).
 * <p>
 * {@link ItemFilter}s represent the series of steps created using an {@link ItemFilterBuilder}, and apply those steps to the sets of
 * supported and default items provided by the caller.
 *
 * @param <I> the type of item being filtered/matched.
 */
public interface ItemFilter<I extends NamedItem> {

    /**
     * The result of applying a filter to a set of items.
     */
    public interface FilterResult<I> {

        /**
         * Obtains the set of items that were {@link ItemFilterBuilder#add(ItemFilterBuilder.Filter) matched} (and retained) by the filter. <br>
         * The set is ordered according to the original ordering of the supported items, and any filtering any sorting steps applied.
         *
         * @return the set of included items, which may be empty but not <code>null</code>.
         */
        public Set<I> getIncluded();

        /**
         * Obtains the {@link NamedItem#getName() names} of the included items, in the order they were produced by the filtering and
         * sorting.
         *
         * @return the names of the included items, which may be empty but not <code>null</code>.
         */
        public String[] getIncludedNames();

        /**
         * Obtains the set of items that were {@link ItemFilterBuilder#delete(org.archie.groktls.ItemFilterBuilder.Filter) excluded} by
         * criteria in the filter.
         *
         * @return the set of excluded items, which may be empty but not <code>null</code>.
         */
        public Set<I> getExcluded();

        /**
         * Obtains the set of items that were {@link ItemFilterBuilder#blacklist(ItemFilterBuilder.Filter) blacklisted} by criteria in the
         * filter.
         *
         * @return the set of blacklisted items, which may be empty but not <code>null</code>.
         */
        public Set<I> getBlacklisted();

    }

    /**
     * Filters and orders a set of items provided by a TLS implementation using the criteria in this filter.
     *
     * @param supportedItems the set of supported items to match against.
     * @param defaultItems the default items, which should be a subset of the supported items.
     * @return the result of applying this filter to the provided items.
     */
    public FilterResult<I> filter(List<String> supportedItems, List<String> defaultItems);

    /**
     * Filters and orders a set of items provided by a TLS implementation using the criteria in this filter.
     *
     * @param supportedItems the set of supported items to match against.
     * @param defaultItems the default items, which should be a subset of the supported items.
     * @return the result of applying this filter to the provided items.
     */
    public FilterResult<I> filter(String[] supportedCipherSuites, String[] defaultCipherSuites);

    /**
     * Filters and orders a set of items provided by a TLS implementation using the criteria in this filter.
     *
     * @param context an {@link SSLContext#init(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom)
     *            initialised} {@link SSLContext}, from which the {@link SSLContext#getSupportedSSLParameters() supported} and
     *            {@link SSLContext#getDefaultSSLParameters() default} items will be obtained.
     * @return the result of applying this filter to the items provided by the SSLContext.
     */
    public FilterResult<I> filter(SSLContext context);

}
