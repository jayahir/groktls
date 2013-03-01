package org.archie.groktls;

import java.util.Comparator;
import java.util.Set;

import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.cipher.CipherSuiteFilters;

/**
 * A builder for {@link CipherSuiteFilter}s. <br>
 * Implementations are usually obtained via {@link GrokTLS#createCipherSuiteFilterBuilder()}.
 * <p>
 * This builder generally follows the approach of the <a href="http://www.openssl.org/docs/apps/ciphers.html">OpenSSL ciphers</a> command,
 * which is also commonly exposed through web server configuration.
 * <p>
 * Cipher suite filters are built up as a sequence of operations that when applied together produce an ordered set of cipher suites. <br>
 * Each of the operations takes a Filter that is used to match a set of cipher suites from the set of supported cipher suites. <br>
 * The available operations are:
 * <ul>
 * <li>{@link #add(Filter) inclusion} - the cipher suites matched by the filter are added to the set of matched cipher suites. Any cipher
 * suites that have already been matched remain in their position, while new matches are added to the end of the order.</li>
 * <li>{@link #delete(Filter) exclusion} - the cipher suites matched by the filter are removed from the set of matched cipher suites.</li>
 * <li>{@link #end(Filter) move to end} - any cipher suites matched by the filter that are already in the set of matched cipher suites are
 * moved to the end of the order (equivalent to removing them and re-adding at the end).</li>
 * <li>{@link #blacklist(Filter) blacklist} - any cipher suites matched by the filter are permanently removed from the set of matched cipher
 * suites, and cannot be added back by a later operation.</li>
 * </ul>
 * <p>
 * Common {@link Filter}s are provided by the {@link CipherSuiteFilters} class.
 */
public interface ItemFilterBuilder<I extends NamedItem> {

    /**
     * A filter applied to a cipher suite to see if it matches a criteria.
     */
    public interface Filter<I extends NamedItem> {

        boolean isSafe();

        /**
         * Checks if this filter matches an individual cipher suite.
         * 
         * @param item the {@link CipherSuite} to check.
         * @param defaults the set of default cipher suites provided to the {@link CipherSuiteFilter#filter(java.util.List, java.util.List)
         *            filter} when it is evaluated.
         * @param result TODO
         * @return <code>true</code> iff the cipher suite matches the criteria of this filter.
         */
        boolean matches(I item, Set<I> defaults);
    }

    /**
     * Produces a {@link CipherSuiteFilter} containing the operations applied to this builder.<br>
     * After construction, the internal state of the builder is <b>not</b> reset.
     * 
     * @return the newly constructed {@link CipherSuiteFilter}.
     */
    public ItemFilter<I> build();

    /**
     * Includes the set of cipher suites matched by the filter to the set of matched cipher suites, adding them to the end of the order if
     * they have not already been matched.
     */
    public ItemFilterBuilder<I> add(Filter<I> filter);

    /**
     * Moves any of the cipher suites matched by the filter that have already been matched to the end of the order.
     */
    public ItemFilterBuilder<I> end(Filter<I> filter);

    /**
     * Remove the set of cipher suites matched by the filter from the set of matched cipher suites.
     */
    public ItemFilterBuilder<I> delete(Filter<I> filter);

    /**
     * Removes all of the set of cipher suites matched by the filter from the set of matched cipher suites, and prevents them from being
     * added by a later inclusion.
     */
    public ItemFilterBuilder<I> blacklist(Filter<I> filter);

    public ItemFilterBuilder<I> sort(Comparator<? super I> comparator);

}
