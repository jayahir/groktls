package org.archie.groktls;

import java.util.Collection;
import java.util.Set;

public interface ItemParser<I extends NamedItem> {

    I parse(String itemString);

    Set<? extends I> parse(Collection<String> itemStrings);

}
