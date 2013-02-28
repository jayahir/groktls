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
