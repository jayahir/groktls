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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.archie.groktls.ItemParser;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;
import org.junit.Test;

public class ProtocolVariantParserTest {

    @Test
    public void testVariants() {
        check("SSLv2", "SSL", 2, 0, null);
        check("SSLv2Hello", "SSL", 2, 0, "Hello");
        check("TLSv1", "TLS", 3, 1, null);
        check("TLSv1.0", "TLS", 3, 1, null);
        check("TLSv1.1", "TLS", 3, 2, null);
        check("TLSv1.2", "TLS", 3, 3, null);
    }

    private void check(final String name, final String family, final int major, final int minor, final String pseudo) {
        ItemParser<ProtocolVariant> p = new ProtocolVariantParserImpl();

        ProtocolVariant variant = p.parse(name);

        assertNotNull(name, variant);
        assertEquals(name, name, variant.getName());
        assertEquals(name, family, variant.getFamily());
        assertEquals(name, major, variant.getMajorVersion());
        assertEquals(name, minor, variant.getMinorVersion());
        assertEquals(name, pseudo, variant.getPseudoProtocol());
    }
}
