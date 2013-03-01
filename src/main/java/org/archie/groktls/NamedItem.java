package org.archie.groktls;

/**
 * An item that can be uniquely described by a name.
 */
public interface NamedItem {

    /**
     * The full name of this item (e.g. a TLS cipher suite name, or a TLS protocol variant name).
     */
    public String getName();

}
