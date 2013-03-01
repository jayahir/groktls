package org.archie.groktls;

import java.util.Comparator;
import java.util.Set;

import org.archie.groktls.cipher.CipherSuiteFilters;
import org.archie.groktls.protocol.ProtocolVariantFilters;

/**
 * A builder for {@link ItemFilter}s. <br>
 * Implementations are usually obtained via {@link GrokTLS#createCipherSuiteFilterBuilder()} or
 * {@link GrokTLS#createProtocolVariantFilterBuilder()}.
 * <p>
 *
 * <h4>General Overview</h4> This builder generally follows the approach of the <a
 * href="http://www.openssl.org/docs/apps/ciphers.html">OpenSSL ciphers</a> command, which is also commonly exposed through web server (e.g.
 * Apache HTTPD) configuration.
 * <p>
 * Item filters are built up as a sequence of operations that when applied together produce an ordered set of items. <br>
 * Each of the operations takes a {@link Filter} that is used to match a set of items from the set of supported items.
 * <p>
 *
 * <h4>Operations</h4>
 * The available operations are:
 * <ul>
 * <li>{@link #add(Filter) inclusion} - the items matched by the filter are added to the set of matched items. Any items that have already
 * been matched remain in their position, while new matches are added to the end of the order.</li>
 * <li>{@link #delete(Filter) exclusion} - the items matched by the filter are removed from the set of matched items.</li>
 * <li>{@link #end(Filter) move to end} - any items matched by the filter that are already in the set of matched items are moved to the end
 * of the order (equivalent to removing them and re-adding at the end).</li>
 * <li>{@link #blacklist(Filter) blacklist} - any items matched by the filter are permanently removed from the set of matched items, and
 * cannot be added back by a later operation.</li>
 * <li>{@link #sort(Comparator) sort} - any items matched by steps preceding the sort are sorted according to the provided comparator.
 * </ul>
 * <p>
 *
 * <h4>Safety</h4>
 * Each implementation of {@link ItemFilterBuilder} defines a baseline filter of <em>safeness</em> that is applied to the supported and
 * default items provided to the resulting {@link ItemFilter} prior to any of the defined {@link Filter}s being applied. <br>
 * Some Filter implementations will explicitly be defined as {@link Filter#isSafe() unsafe} in order to allow matching of unsafe items. <br>
 * The one exception to the baseline safety filter is that any items that have already been included by a previous step are eligible for
 * matching by a subsequent safe filter - e.g. items that have been matched by an unsafe filter can be matched and
 * excluded/moved/blacklisted by any filter that matches their essential details, regardless of whether they would be matched from the base
 * supported/default item sets.
 * <p>
 *
 * <h4>Usage</h4>
 *
 * In general, {@link ItemFilterBuilder}s should be used along with the {@link Filter}s provided by static helper classes such as
 * {@link CipherSuiteFilters} and {@link ProtocolVariantFilters}. <br/>
 * Static import of the filters and comparator methods provided by these allows a DSL-like use of the builder to produce an eventual filter.
 *
 * <p>
 * e.g.
 *
 * <pre>
 *  import static org.archie.groktls.protocol.ProtocolVariantFilters.*;
 *  ...
 *  ItemFilter<CipherSuite> filter = new GrokTLS().createCipherSuiteFilterBuilder()
 *                                                .add(cipherSuite("AES"))
 *                                                .delete(mac("SHA"))
 *                                                .sort(byKeyLength())
 *                                                .build();
 * </pre>
 *
 */
public interface ItemFilterBuilder<I extends NamedItem> {

    /**
     * A filter applied to a item to see if it matches a criteria.
     */
    public interface Filter<I extends NamedItem> {

        /**
         * Determines whether this filter should have the baseline definition of safeness applied before it is matched against an item.
         *
         * @return <code>true</code> if this item should not have unrestricted access to unsafe items.
         */
        boolean isSafe();

        /**
         * Checks if this filter matches an individual item.
         *
         * @param item the item to check.
         * @param defaults the set of default items provided to the {@link ItemFilter#filter(java.util.List, java.util.List) filter} when it
         *            is evaluated.
         * @return <code>true</code> iff the item matches the criteria of this filter.
         */
        boolean matches(I item, Set<I> defaults);
    }

    /**
     * Produces a {@link ItemFilter} containing the operations applied to this builder.<br>
     * After construction, the internal state of the builder is <b>not</b> reset.
     *
     * @return the newly constructed {@link ItemFilter}.
     */
    public ItemFilter<I> build();

    /**
     * Includes the set of items matched by the filter to the set of matched items, adding them to the end of the order if they have not
     * already been matched.
     */
    public ItemFilterBuilder<I> add(Filter<I> filter);

    /**
     * Moves any of the items matched by the filter that have already been matched to the end of the order.
     */
    public ItemFilterBuilder<I> end(Filter<I> filter);

    /**
     * Remove the set of items matched by the filter from the set of matched items.
     */
    public ItemFilterBuilder<I> delete(Filter<I> filter);

    /**
     * Removes all of the set of items matched by the filter from the set of matched items, and prevents them from being added by a later
     * inclusion.
     */
    public ItemFilterBuilder<I> blacklist(Filter<I> filter);

    /**
     * Sorts the items matched by previous steps using the supplied comparator.
     *
     * @param comparator the comparator to sort the items with.
     */
    public ItemFilterBuilder<I> sort(Comparator<? super I> comparator);

}
