package org.archie.groktls;

import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;


public interface ItemFilter<I extends NamedItem> {
    /**
     * The result of applying a filter to a set of cipher suites.
     */
    public interface FilterResult<I> {

        /**
         * Obtains the set of cipher suites that were matched (and retained) by the filter. <br>
         * The set is ordered according to the filtering and any sorting applied.
         * 
         * @return the set of included cipher suites, which may be empty but not <code>null</code>.
         */
        public Set<I> getIncluded();

        /**
         * Obtains the cipher suite names of the included cipher suites, in the order they were produced by the filtering and sorting.
         * 
         * @return the names of the included cipher suites, which may be empty but not <code>null</code>.
         */
        public String[] getIncludedNames();

        /**
         * Obtains the set of cipher suites that were excluded by criteria in the filter.
         * 
         * @return the set of excluded cipher suites, which may be empty but not <code>null</code>.
         */
        public Set<I> getExcluded();

        /**
         * Obtains the set of cipher suites that were blacklisted by criteria in the filter.
         * 
         * @return the set of blacklisted cipher suites, which may be empty but not <code>null</code>.
         */
        public Set<I> getBlacklisted();

    }

    /**
     * Filters and orders a set of cipher suites provided by a TLS implementation using the criteria in this filter.
     * 
     * @param supportedCipherSuites
     *            the set of cipher suites supported to match against.
     * @param defaultCipherSuites
     *            the default cipher suites, which should be a subset of the supported cipher suites.
     * @return the result of applying this filter to the provided cipher suites.
     */
    public FilterResult<I> filter(List<String> supportedCipherSuites, List<String> defaultCipherSuites);

    /**
     * Filters and orders a set of cipher suites provided by a TLS implementation using the criteria in this filter.
     * 
     * @param supportedCipherSuites
     *            the set of cipher suites supported to match against.
     * @param defaultCipherSuites
     *            the default cipher suites, which should be a subset of the supported cipher suites.
     * @return the result of applying this filter to the provided cipher suites.
     */
    public FilterResult<I> filter(String[] supportedCipherSuites, String[] defaultCipherSuites);

    /**
     * Filters and orders a set of cipher suites provided by a TLS implementation using the criteria in this filter.
     * 
     * @param context
     *            an initialised {@link SSLContext}, from which the {@link SSLContext#getSupportedSSLParameters() supported} and
     *            {@link SSLContext#getDefaultSSLParameters() default} {@link SSLParameters#getCipherSuites() cipher suites will be
     *            obtained}.
     * @return the result of applying this filter to the cipher suites provided by the SSLContext.
     */
    public FilterResult<I> filter(SSLContext context);

}
