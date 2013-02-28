package org.archie.groktls.impl.protocol;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.archie.groktls.ItemParser;
import org.archie.groktls.protocol.ProtocolVariant;

public class ProtocolVariantParserImpl implements ItemParser<ProtocolVariant> {


    public static final ProtocolVariant TLSv1 = new ProtocolVariantImpl("TLSv1", "TLS", 3, 1, null);
    public static final ProtocolVariant SSLv3 = new ProtocolVariantImpl("SSLv3", "SSL", 3, 0, null);

    private static final Pattern PROTOCOL_VARIANT = Pattern.compile("([A-Z]+)v([0-9]+)(\\.)?([0-9]+)?([A-Za-z]+)?");

    @Override
    public Set<ProtocolVariant> parse(final Collection<String> protocolVariant) {
        Set<ProtocolVariant> parsed = new LinkedHashSet<ProtocolVariant>();
        for (String variant : protocolVariant) {
            final ProtocolVariant pv = parse(variant);
            if (pv != null) {
                parsed.add(pv);
            }
            // TODO: What to do with unparseable...
        }
        return parsed;
    }

    @Override
    public ProtocolVariant parse(final String protocolVariant) {
        Matcher matcher = PROTOCOL_VARIANT.matcher(protocolVariant);
        if (matcher.matches()) {
            String family = matcher.group(1);
            String majorVer = matcher.group(2);
            String minorVer = matcher.group(4);
            String pseudoProtocol = matcher.group(5);

            int major;
            int minor = 0;
            try {
                major = Integer.parseInt(majorVer);
                if (minorVer != null) {
                    minor = Integer.parseInt(minorVer);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(String.format("Could not understand protocol variant %s", protocolVariant));
            }
            if ("TLS".equals(family)) {
                // TLSv1.0 == SSLv3.1
                major += (TLSv1.getMajorVersion() - 1);
                minor += TLSv1.getMinorVersion();
            }
            return new ProtocolVariantImpl(protocolVariant, family, major, minor, pseudoProtocol);
        }
        return null;
    }


}
