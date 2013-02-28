package org.archie.groktls.impl.filter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterBuilder;
import org.archie.groktls.NamedItem;
import org.archie.groktls.impl.filter.ItemFilterImpl.Step;
import org.archie.groktls.impl.filter.ItemFilterStep.Op;

public abstract class ItemFilterBuilderImpl<I extends NamedItem> implements ItemFilterBuilder<I> {

    private final List<Step<I>> steps = new ArrayList<Step<I>>();

    public ItemFilterBuilderImpl() {
    }

    protected final List<Step<I>> getSteps() {
        return this.steps;
    }

    @Override
    public abstract ItemFilter<I> build();

    protected abstract Step<I> createStep(final Op op, final Filter<I> filter);

    public ItemFilterBuilder<I> step(final Op op, final Filter<I> filter) {
        this.steps.add(createStep(op, filter));
        return this;
    }

    @Override
    public ItemFilterBuilder<I> add(final Filter<I> filter) {
        return step(Op.ADD, filter);
    }

    @Override
    public ItemFilterBuilder<I> end(final Filter<I> filter) {
        return step(Op.MOVE_TO_END, filter);
    }

    @Override
    public ItemFilterBuilder<I> delete(final Filter<I> filter) {
        return step(Op.DELETE, filter);
    }

    @Override
    public ItemFilterBuilder<I> blacklist(final Filter<I> filter) {
        return step(Op.BLACKLIST, filter);
    }

    @Override
    public ItemFilterBuilder<I> sort(final Comparator<? super I> comparator) {
        this.steps.add(new ItemSortStep<I>(comparator));
        return this;
    }

}
