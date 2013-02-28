package org.archie.groktls.protocol;

import org.archie.groktls.NamedItem;

public interface ProtocolVariant extends Comparable<ProtocolVariant>, NamedItem {

    public String getFamily();

    public int getMajorVersion();

    public int getMinorVersion();

    public String getPseudoProtocol();

    @Override
    public boolean equals(Object obj);

    @Override
    public int hashCode();
}
