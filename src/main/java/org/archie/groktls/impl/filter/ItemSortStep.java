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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import org.archie.groktls.NamedItem;
import org.archie.groktls.impl.filter.ItemFilterImpl.FilterResultImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl.Step;

public class ItemSortStep<I extends NamedItem> implements Step<I> {

    private final Comparator<? super I> comparator;

    public ItemSortStep(final Comparator<? super I> comparator) {
        this.comparator = comparator;
    }

    @Override
    public void apply(final FilterResultImpl<I> result, final Set<I> supported, final Set<I> defaults) {
        final List<I> current = new ArrayList<I>(result.included);
        Collections.sort(current, this.comparator);
        result.included.clear();
        result.included.addAll(current);
    }

}
