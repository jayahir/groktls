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

import java.util.LinkedHashSet;
import java.util.Set;

import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.NamedItem;
import org.archie.groktls.impl.filter.ItemFilterImpl.FilterResultImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl.Step;

public abstract class ItemFilterStep<I extends NamedItem> implements Step<I> {

    public static enum Op {
        ADD,
        MOVE_TO_END,
        DELETE,
        BLACKLIST
    }

    private final Op op;
    private final Filter<I> filter;

    protected ItemFilterStep(final Op op, final Filter<I> filter) {
        if ((op == null) || (filter == null)) {
            throw new IllegalArgumentException("Operation and filter are required.");
        }
        this.op = op;
        this.filter = filter;
    }

    @Override
    public void apply(final FilterResultImpl<I> result, final Set<I> supported, final Set<I> defaults) {
        final Set<I> ciphers = new LinkedHashSet<I>();

        for (final I cipher : supported) {
            // Supported items are guarded by safety of filter
            if (this.filter.isSafe() && !isSafe(cipher)) {
                continue;
            }
            if (this.filter.matches(cipher, defaults)) {
                ciphers.add(cipher);
            }
        }
        // Once unsafe items are matched, they can be matched by any filter
        // e.g. UNSAFE:-eNULL
        for (final I cipher : result.included) {
            if (this.filter.matches(cipher, defaults)) {
                ciphers.add(cipher);
            }
        }

        switch (this.op) {
        case BLACKLIST:
            result.excluded.removeAll(ciphers);
            result.included.removeAll(ciphers);
            result.blacklisted.addAll(ciphers);
            break;
        case DELETE:
            ciphers.removeAll(result.blacklisted);
            result.included.removeAll(ciphers);
            result.excluded.addAll(ciphers);
            break;
        case ADD:
            ciphers.removeAll(result.blacklisted);
            result.excluded.removeAll(ciphers);
            result.included.addAll(ciphers);
            break;
        case MOVE_TO_END:
        default:
            ciphers.retainAll(result.included);
            result.included.removeAll(ciphers);
            result.included.addAll(ciphers);
            break;

        }
    }

    protected abstract boolean isSafe(final I cipher);

}
