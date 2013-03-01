package org.archie.groktls;

public interface ItemFilterSpecParser<I extends NamedItem> {

    ItemFilter<I> parse(String filterSpec);

}
