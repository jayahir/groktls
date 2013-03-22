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

import static org.archie.groktls.protocol.ProtocolVariantFilters.*;

import java.util.Arrays;
import java.util.List;

import org.archie.groktls.AbstractItemFilterTest;
import org.archie.groktls.ItemFilter;
import org.archie.groktls.ItemFilterSpecParser;
import org.archie.groktls.impl.protocol.filter.ProtocolVariantFilterBuilderImpl;
import org.archie.groktls.impl.protocol.filter.ProtocolVariantFilterSpecParserImpl;
import org.junit.Test;

public class ProtocolVariantFilterTest extends AbstractItemFilterTest<ProtocolVariant> {

    public static final String SSLv2HELLO = "SSLv2Hello";
    public static final String SSLv2 = "SSLv2";
    public static final String SSLv3 = "SSLv3";
    public static final String TLSv1 = "TLSv1";
    public static final String TLSv11 = "TLSv1.1";
    public static final String TLSv12 = "TLSv1.2";

    private static final List<String> ALL_PROTOCOLS = Arrays.asList(TLSv1, TLSv11, TLSv12, SSLv2HELLO, SSLv2, SSLv3);

    @Override
    protected ItemFilterSpecParser<ProtocolVariant> createSpecParser() {
        return new ProtocolVariantFilterSpecParserImpl();
    }

    @Test
    public void testAll() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(TLSv1, TLSv11, TLSv12, SSLv3);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(all()).build();
        checkResult("ALL", filter, supported, expected);
    }

    @Test
    public void testComplementOfAll() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(SSLv2HELLO, SSLv2);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(complementOfAll()).build();
        checkResult("COMPLEMENTOFALL", filter, supported, expected);
        checkResult("UNSAFE", filter, supported, expected);
    }

    @Test
    public void testDefault() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> defaults = Arrays.asList(TLSv1, TLSv11, SSLv3, SSLv2);
        final List<String> expected = Arrays.asList(TLSv1, TLSv11, SSLv3);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(defaults()).build();
        checkResult("DEFAULT", filter, supported, expected, defaults);
    }

    @Test
    public void testComplementOfDefault() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> defaults = Arrays.asList(TLSv1, TLSv11, SSLv3);
        final List<String> expected = Arrays.asList(TLSv12);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(complementOfDefaults()).build();
        checkResult("COMPLEMENTOFDEFAULT", filter, supported, expected, defaults);
    }

    @Test
    public void testFamily() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(TLSv1, TLSv11, TLSv12);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(family("TLS")).build();
        checkResult("fTLS", filter, supported, expected);
    }

    @Test
    public void testVariant() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(TLSv1);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(protocolVariant("TLSv1")).build();
        checkResult("TLSv1", filter, supported, expected);
    }

    @Test
    public void testPseudoProtocols() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList();
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(pseudoProtocols()).build();
        checkResult("PSEUDO", filter, supported, expected);
    }

    @Test
    public void testUnsafeAndPseudoProtocols() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(SSLv2HELLO);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(and(complementOfAll(), pseudoProtocols())).build();
        checkResult("SUPPORTED+PSEUDO", filter, supported, expected);
        checkResult("UNSAFE+PSEUDO", filter, supported, expected);
    }

    @Test
    public void testMinVersion() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(TLSv1, TLSv11, TLSv12);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(minimumVersion(3, 1)).build();
        checkResult(">=TLSv1", filter, supported, expected);
    }

    @Test
    public void testMinVersionString() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(TLSv1, TLSv11, TLSv12);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(minimumVersion(TLSv1)).build();
        checkResult(">=TLSv1", filter, supported, expected);
    }

    @Test
    public void testSpacesInFilterSpec() {
        final List<String> supported = ALL_PROTOCOLS;
        final List<String> expected = Arrays.asList(TLSv1, TLSv11);
        ItemFilter<ProtocolVariant> filter = new ProtocolVariantFilterBuilderImpl().add(protocolVariant(TLSv1))
                .add(protocolVariant(TLSv11)).build();
        checkResult("TLSv1, TLSv1.1", filter, supported, expected);
    }

}
