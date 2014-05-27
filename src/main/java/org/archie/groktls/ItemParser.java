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

    /**
     * Parses a series of itemNames.
     *
     * @param itemNames the names of the items to parse.
     * @param unparseableNames the names of the items that could not be parsed.
     * @return the parsed items, in the order the names were provided for parsing.
     */
    Set<? extends I> parse(Collection<String> itemNames, Collection<String> unparseableNames);

}
