package org.archie.groktls;

import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterSpecParser;
import org.archie.groktls.NamedItem;
import org.archie.groktls.ItemFilter.FilterResult;

public abstract class AbstractItemFilterTest<I extends NamedItem> {

    protected void checkResult(final String cipherSpec,
                               final ItemFilter<I> filter,
                               final List<String> supported,
                               final List<String> expected) {
        checkResult(cipherSpec, filter, supported, expected, Collections.<String> emptyList());
    }

    protected void checkResult(final String cipherSpec,
                               final ItemFilter<I> filter,
                               final List<String> supported,
                               final List<String> expected,
                               final List<String> defaults) {
        checkResult(cipherSpec, filter, supported, expected, defaults, Collections.<String> emptyList());
    }

    protected void checkResult(final String cipherSpec,
                               final ItemFilter<I> filter,
                               final List<String> supported,
                               final List<String> expected,
                               final List<String> defaults,
                               final List<String> blacklisted) {
        FilterResult<I> fromBuilder = filter.filter(supported, defaults);
        FilterResult<I> fromSpec = createSpecParser().parse(cipherSpec).filter(supported, defaults);

        checkResult(cipherSpec + " (builder)", fromBuilder, expected, blacklisted);
        checkResult(cipherSpec + " (spec)", fromSpec, expected, blacklisted);
    }

    protected abstract ItemFilterSpecParser<I> createSpecParser();

    private void checkResult(final String name, final FilterResult<I> result, final List<String> expected, final List<String> blacklisted) {
        Set<String> included = compress(result.getIncluded());
        // Set<String> excluded = compress(result.getExcluded());
        Set<String> banned = compress(result.getBlacklisted());

        Set<String> missed = new LinkedHashSet<String>(expected);
        missed.removeAll(included);

        Set<String> extra = new LinkedHashSet<String>(included);
        extra.removeAll(expected);

        if (!missed.isEmpty()) {
            System.err.println(included);
            fail(String.format("%s: missing expected ciphers %s", name, missed));
        }
        if (!extra.isEmpty()) {
            fail(String.format("%s: extra ciphers matched %s", name, extra));
        }

        Iterator<String> ciphers = included.iterator();
        Iterator<String> comps = expected.iterator();
        int i = 1;
        while (ciphers.hasNext()) {
            String cipher = ciphers.next();
            String comp = comps.next();

            if (!cipher.equals(comp)) {
                System.err.println(included);
                System.err.println(expected);
                fail(String.format("%s: cipher at position %d expected %s but got %s", name, i, comp, cipher));
            }
            i++;
        }

        Set<String> missedBlack = new LinkedHashSet<String>(blacklisted);
        missedBlack.removeAll(banned);
        Set<String> extraBlack = new LinkedHashSet<String>(banned);
        extraBlack.removeAll(blacklisted);

        if (!missedBlack.isEmpty()) {
            fail(String.format("%s: missing blacklisted ciphers %s", name, missedBlack));
        }
        if (!extraBlack.isEmpty()) {
            fail(String.format("%s: extra ciphers blacklisted %s", name, extraBlack));
        }
        // TODO: Test excluded
    }

    private Set<String> compress(final Set<I> results) {
        Set<String> ciphers = new LinkedHashSet<String>();
        for (I result : results) {
            ciphers.add(result.getName());
        }
        return ciphers;
    }

}