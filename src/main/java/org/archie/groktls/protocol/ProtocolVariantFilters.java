package org.archie.groktls.protocol;

import java.util.Set;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterBuilder;
import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;

/**
 * Common {@link Filter}s that can be applied in a {@link ItemFilterBuilder} to filter a set of {@link ProtocolVariant}s.
 * <p>
 * Unless noted, all filters imply that they will only include {@link #isSafe(ProtocolVariant) safe protocol variants} - i.e. unless the
 * filter is {@link #and(ProtocolVariant...) concatenated} with an unsafe filter, or is applied to already matched results that are unsafe,
 * then unsafe protocol variants will not be matched.
 * <p>
 * The filters provided here behave in the same way as the filters in {@link ProtocolVariantFilters} with regard to matching unsafe filters
 * .
 */
public class ProtocolVariantFilters {

    /**
     * A {@link Filter} for {@link ProtoVariant}s.
     */
    public interface ProtocolVariantFilter extends Filter<ProtocolVariant> {
    }

    /**
     * A filter that will by default only include unsafe protocol variants.
     */
    private abstract static class UnsafeFilter implements ProtocolVariantFilter {
        @Override
        public boolean isSafe() {
            return false;
        }

    }

    /**
     * A filter that will by default only include safe protocol variants.
     */
    private abstract static class SafeFilter implements ProtocolVariantFilter {
        @Override
        public boolean isSafe() {
            return true;
        }
    }

    /**
     * Matches all of the {@link ItemFilter#filter(java.util.List, java.util.List) supported protocol variants}, with the exception of any
     * protocol variants that are considered {@link #isSafe(ProtocolVariant) unsafe} - these unsafe protocol variants can be matched using
     * {@link #complementOfAll()}.
     * <p>
     * <em>Filter spec usage:</em> <code>ALL</code>.
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
     * Matches all of the {@link ItemFilter#filter(java.util.List, java.util.List) supported protocol variants} including any that are
     * considered {@link #isSafe(ProtocolVariant) unsafe}.
     * <p>
     * <b>Unsafe:</b> this will match <b>unsafe</b> protocol variants.
     * <p>
     * <em>Filter spec usage:</em> <code>SUPPORTED</code>.
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
     * Matches any supported protocol variants that are not matched by {@link #all()}. <br>
     * This will include any of the {@link #isSafe(ProtocolVariant) unsafe} protocol variants excluded by {@link #all()}.
     * <p>
     * <b>Unsafe:</b> this will match <b>unsafe</b> protocol variants.
     * <p>
     * <em>Filter spec usage:</em> <code>COMPLEMENTOFALL</code> or <code>UNSAFE</code>.
     */
    public static ProtocolVariantFilter complementOfAll() {
        return new UnsafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return !ProtocolVariantFilters.isSafe(item);
            }
        };
    }

    /**
     * Determines if a protocol variant is considered safe by filter rules.
     * <p>
     * Currently a protocol variant is considered safe iff:
     * <ul>
     * <li>It is later than or equal to <code>SSLv3</code> (e.g. the version number is >= 3.0)</li>
     * </ul>
     *
     * @param item the protocol variant to check.
     * @return <code>true</code> iff the protocol variant is safe to use.
     */
    public static boolean isSafe(final ProtocolVariant item) {
        // < SSLv3 not deemed safe
        return ProtocolVariantParserImpl.SSLv3.compareTo(item) <= 0;
    }

    /**
     * Matches any of the {@link ItemFilter#filter(java.util.List, java.util.List) default protocol variants} that are also matched by
     * {@link #all()}. <br>
     * This will not include any of the unsafe protocol variants excluded by {@link #all()}, even if they are specified as defaults during
     * the filter invocation.
     * <p>
     * <em>Filter spec usage:</em> <code>DEFAULT</code>.
     */
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
     * Matches any of the protocol variants matched by {@link #all()} that are not in the {@link #defaults() defaults}. <br>
     * This will not include any of the unsafe protocol variants excluded by {@link #all()} - i.e. {@link #defaults() defaults} and
     * {@link #complementOfDefaults()} are subsets of the safe default protocol variants.
     * <p>
     * <em>Filter spec usage:</em> <code>COMPLEMENTOFDEFAULT</code>.
     */
    public static ProtocolVariantFilter complementOfDefaults() {
        return isDefault(false);
    }

    /**
     * Matches protocol variants from a specific {@link ProtocolVariant#getFamily() family}.
     *
     * @param family the name of the family (e.g. <code>TLS</code>).
     *            <p>
     *            <em>Filter spec usage:</em> <code>fFAMILY</code> e.g. <code>fTLS</code>.
     */
    public static ProtocolVariantFilter family(final String family) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return family.equals(item.getFamily());
            }
        };
    }

    /**
     * Matches a single protocol variant by name. The provided protocol variant name is not parsed and is directly matched.
     * <p>
     * <em>Filter spec usage:</em> literal variant, e.g. <code>TLSv1.1</code>.
     * 
     * @param variant the protocol variant name to match.
     */
    public static ProtocolVariantFilter protocolVariant(final String variant) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return variant.equals(item.getName());
            }
        };
    }

    /**
     * Matches {@link ProtocolVariant#getPseudoProtocol() pseudo protocols}.
     * <p>
     * <em>Filter spec usage:</em> <code>PSEUDO</code>.
     */
    public static ProtocolVariantFilter pseudoProtocols() {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return (item.getPseudoProtocol() != null);
            }
        };
    }

    /**
     * Matches protocol variants with a version number equal to or greater than the specified version.
     * <p>
     * <em>Filter spec usage:</em> no equivalent.
     *
     * @param major the minimum major version.
     * @param minor the minimum minor version if the major version is equal to the minimum.
     */
    public static ProtocolVariantFilter minimumVersion(final int major, final int minor) {
        return new SafeFilter() {
            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                return (item.getMajorVersion() >= major) && (item.getMinorVersion() >= minor);
            }
        };
    }

    /**
     * Matches protocol variants with a version number equal to or greater than the specified protocol variant.
     * <p>
     * <em>Filter spec usage:</em> <code>>=TLSv1.2</code>.
     *
     * @param protocolVariant the full name of a protocol variant (e.g. <code>TLSv1.2</code>), which will be parsed and used as the base
     *            version number.
     */
    public static ProtocolVariantFilter minimumVersion(final String protocolVariant) {
        final ProtocolVariant pv = new ProtocolVariantParserImpl().parse(protocolVariant);
        if (pv == null) {
            throw new IllegalArgumentException(String.format("Unable to parse %s", protocolVariant));
        }
        return minimumVersion(pv.getMajorVersion(), pv.getMinorVersion());
    }

    /**
     * Matches any protocol variants not matched by a specified filter.
     * <p>
     * <b>Safety:</b> the filter produced is safe iff the negated filter is safe.
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
     * Matches any protocol variants matched by any of the specified filters.
     * <p>
     * <b>Safety:</b> the filter produced is safe iff the first filter combines is safe.
     */
    public static ProtocolVariantFilter or(final ProtocolVariantFilter... filters) {
        return new ProtocolVariantFilter() {
            @Override
            public boolean isSafe() {
                return (filters.length > 0) && filters[0].isSafe();
            }

            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                for (final ProtocolVariantFilter filter : filters) {
                    if (filter.matches(item, defaults)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    /**
     * Matches any protocol variants matched by all of the specified filters.
     * <p>
     * <b>Safety:</b> the filter produced is safe iff the first filter combines is safe.
     */
    public static ProtocolVariantFilter and(final ProtocolVariantFilter... filters) {
        return new ProtocolVariantFilter() {
            @Override
            public boolean isSafe() {
                return (filters.length > 0) && filters[0].isSafe();
            }

            @Override
            public boolean matches(final ProtocolVariant item, final Set<ProtocolVariant> defaults) {
                for (final ProtocolVariantFilter filter : filters) {
                    if (!filter.matches(item, defaults)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }
}
