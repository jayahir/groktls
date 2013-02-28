package org.archie.groktls.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.archie.groktls.ItemParser;
import org.archie.groktls.impl.protocol.ProtocolVariantParserImpl;
import org.archie.groktls.protocol.ProtocolVariant;
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
