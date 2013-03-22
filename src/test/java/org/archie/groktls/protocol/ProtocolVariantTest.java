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

import static org.junit.Assert.assertTrue;

import org.archie.groktls.impl.protocol.ProtocolVariantImpl;
import org.junit.Test;

public class ProtocolVariantTest {

    @Test
    public void testOrdering() {
        ProtocolVariant p10 = new ProtocolVariantImpl("TLSv1", "TLS", 3, 1, null);
        ProtocolVariant p10b = new ProtocolVariantImpl("SSLv3.1", "SSL", 3, 1, null);
        ProtocolVariant p11 = new ProtocolVariantImpl("TLSv1.1", "TLS", 3, 2, null);
        ProtocolVariant p12 = new ProtocolVariantImpl("TLSv1.2", "TLS", 3, 3, null);

        assertTrue(p10.compareTo(p10b) == 0);
        assertTrue(p10b.compareTo(p10) == 0);

        assertTrue(p10.compareTo(p11) < 0);
        assertTrue(p11.compareTo(p10) > 0);

        assertTrue(p11.compareTo(p12) < 0);
        assertTrue(p12.compareTo(p11) > 0);

        assertTrue(p11.compareTo(p12) < 0);
        assertTrue(p12.compareTo(p11) > 0);
    }

}
