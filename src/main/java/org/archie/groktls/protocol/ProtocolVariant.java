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
package org.archie.groktls.protocol;

import org.archie.groktls.NamedItem;

/**
 * A variant of version of the SSL/TLS protocols.
 * <p>
 * e.g. <code>SSLv3</code>, <code>TLSv1.2</code> etc.
 */
public interface ProtocolVariant extends Comparable<ProtocolVariant>, NamedItem {

    public static final String FAMILY_TLS = "TLS";
    public static final String FAMILY_SSL = "SSL";

    /**
     * Obtains the family of the protocol variant (one of {@link #FAMILY_SSL SSL} or {@link #FAMILY_TLS TLS}).
     */
    public String getFamily();

    /**
     * Obtains the major version of this protocol variant, according to its position in the SSL and TLS protocol revision history.
     * <p>
     * The major version is 1 to 3 for SSL versions 1 to 3 respectively, and 3 for TLSv1 (which is internally identified as 3.1).
     */
    public int getMajorVersion();

    /**
     * Obtains the minor version of this protocol variant, according to its position in the SSL and TLS protocol revision history.
     * <p>
     * The minor version is 0 for SSL versions 1 to 3, and one more than the displayed minor version for TLSv1, TLSv1.1 etc. (since TLS v1
     * is internally identified as 3.1).
     */
    public int getMinorVersion();

    /**
     * Obtains the part of the name of a pseudo protocol variant following the normal protocol variant name. <br>
     * e.g. <code>SSLv2Hello</code> would return <code>Hello</code> as the pseudo protocol.
     *
     * @return the pseudoprotocol string, or <code>null</code> if this is not a pseudo-protocol.
     */
    public String getPseudoProtocol();

    @Override
    public boolean equals(Object obj);

    @Override
    public int hashCode();
}
