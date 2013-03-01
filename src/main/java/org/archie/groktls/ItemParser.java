package org.archie.groktls;

import java.util.Collection;
import java.util.Set;

/**
 *
 * @param <I> the type of item being parsed.
 */
public interface ItemParser<I extends NamedItem> {

    /**
     * Parses an item name into an object describing the various parts specified or implied by the name.
     * 
     * @param itemName the {@link NamedItem#getName()} of the item.
     * @return the parsed information from the item name, or <code>null</code> if the name could not be parsed.
     */
    I parse(String itemName);

    /**
     * Parses a series of itemNames.
     *
     * @param itemNames the names of the items to parse.
     * @return the parsed items, in the order the names were provided for parsing.
     */
    Set<? extends I> parse(Collection<String> itemNames);

}
