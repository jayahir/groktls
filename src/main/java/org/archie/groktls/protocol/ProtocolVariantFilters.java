package org.archie.groktls.protocol;

import java.util.Set;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;

public class ProtocolVariantFilters {

    public interface ProtocolVariantFilter extends Filter<ProtocolVariant> {
    }

    private abstract static class UnsafeFilter implements ProtocolVariantFilter {
        @Override
        public boolean isSafe() {
            return false;
        }

    }

    private abstract static class SafeFilter implements ProtocolVariantFilter {
        @Override
        public boolean isSafe() {
            return true;
        }
    }

    /**
     * Matches all of the {@link ItemFilter#filter(java.util.List, java.util.List) supported cipher suites}, with the exception of any
     * cipher suites with <code>NULL</code> key exchange, authentication or encryption (these can be matched using
     * {@link #complementOfAll()}.
     * <p>
     * This differs from the OpenSSL <b>ALL</b> cipher suite in that it also excludes <code>NULL</code> key exchange and authentication
     * ciphers.
     */
    public static ProtocolVariantFilter all() {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                // TODO: Note the non-equivalence to SAFE (i.e. in the context of SUPPORTED:-ALL)
                return true;
            }
        };
    }

    /**
     * Matches all of the {@link ItemFilter#filter(java.util.List, java.util.List) supported cipher suites}, <b>including</b> cipher suites
     * with <code>NULL</code> key exchange, authentication or encryption.
     * <p>
     */
    public static ProtocolVariantFilter supportedIncludingUnsafe() {
        return new UnsafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return true;
            }
        };
    }

    /**
     * Matches any supported ciphers that are not matched by {@link #all()}. <br>
     * This will include any of the <code>NULL</code> cipher suites excluded by {@link #all()}.
     */
    public static ProtocolVariantFilter complementOfAll() {
        return new UnsafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return !ProtocolVariantFilters.isSafe(item);
            }
        };
    }

    public static boolean isSafe(final ProtocolVariant item) {
        // < SSLv3 not deemed safe
        return ProtocolVariantParserImpl.SSLv3.compareTo(item) <= 0;
    }

    public static ProtocolVariantFilter defaults() {
        return isDefault(true);
    }

    private static ProtocolVariantFilter isDefault(final boolean include) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return (include == defaults.contains(item));
            }
        };
    }

    /**
     * Matches any of the cipher suites matched by {@link #all()} that are not in the {@link #defaults() defaults}. <br>
     * This will not include any of the <code>NULL</code> cipher suites excluded by {@link #all()}.
     */
    public static ProtocolVariantFilter complementOfDefaults() {
        return isDefault(false);
    }

    public static ProtocolVariantFilter family(final String family) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return family.equals(item.getFamily());
            }
        };
    }

    public static ProtocolVariantFilter protocolVariant(final String variant) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return variant.equals(item.getName());
            }
        };
    }

    public static ProtocolVariantFilter pseudoProtocols() {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return (item.getPseudoProtocol() != null);
            }
        };
    }

    public static ProtocolVariantFilter minimumVersion(final int major, final int minor) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return (item.getMajorVersion() >= major) && (item.getMinorVersion() >= minor);
            }
        };
    }

    public static ProtocolVariantFilter minimumVersion(final String protocolVariant) {
        final ProtocolVariant pv = new ProtocolVariantParserImpl().parse(protocolVariant);
        if (pv == null) {
            throw new IllegalArgumentException(String.format("Unable to parse %s", protocolVariant));
        }
        return minimumVersion(pv.getMajorVersion(), pv.getMinorVersion());
    }

    /**
     * Matches any cipher suites not matched by a specified filter.
     *
     * @param filter
     *            the filter to negate.
     */
    public static ProtocolVariantFilter not(final ProtocolVariantFilter filter) {
        return new ProtocolVariantFilter() {
            @Override
            public boolean isSafe() {
                return filter.isSafe();
            }

            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return !filter.matches(item, defaults);
            }
        };
    }

    /**
     * Matches any cipher suites matched by any of the specified filters.
     */
    public static ProtocolVariantFilter or(final ProtocolVariantFilter... filters) {
        return new ProtocolVariantFilter() {
            @Override
            public boolean isSafe() {
                return (filters.length > 0) && filters[0].isSafe();
            }

            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                for (ProtocolVariantFilter filter : filters) {
                    if (filter.matches(item, defaults)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    /**
     * Matches any cipher suites matched by all of the specified filters.
     */
    public static ProtocolVariantFilter and(final ProtocolVariantFilter... filters) {
        return new ProtocolVariantFilter() {
            @Override
            public boolean isSafe() {
                return (filters.length > 0) && filters[0].isSafe();
            }

            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                for (ProtocolVariantFilter filter : filters) {
                    if (!filter.matches(item, defaults)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }
}
