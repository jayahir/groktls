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
        final Set<ProtocolVariant> parsed = new LinkedHashSet<ProtocolVariant>();
        for (final String variant : protocolVariant) {
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
        final Matcher matcher = PROTOCOL_VARIANT.matcher(protocolVariant);
        if (matcher.matches()) {
            final String family = matcher.group(1);
            final String majorVer = matcher.group(2);
            final String minorVer = matcher.group(4);
            final String pseudoProtocol = matcher.group(5);

            int major;
            int minor = 0;
            try {
                major = Integer.parseInt(majorVer);
                if (minorVer != null) {
                    minor = Integer.parseInt(minorVer);
                }
            } catch (final NumberFormatException e) {
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
