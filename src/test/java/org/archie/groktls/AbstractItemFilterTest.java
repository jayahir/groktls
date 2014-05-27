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
package org.archie.groktls;

import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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

        if (!fromBuilder.getUnparseableNames().isEmpty()) {
            // Should cover supported and defaults
            fail(String.format("Unparseable names: %s", fromBuilder.getUnparseableNames()));
        }

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
            System.err.println("Matched: " + included);
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
                System.err.println("Matched: " + included);
                System.err.println("Expected: " + expected);
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
