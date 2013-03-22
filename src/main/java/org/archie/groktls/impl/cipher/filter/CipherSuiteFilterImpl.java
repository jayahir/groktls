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
package org.archie.groktls.impl.cipher.filter;

import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.impl.cipher.CipherSuiteParserImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl;

public class CipherSuiteFilterImpl extends ItemFilterImpl<CipherSuite> {

    private final CipherSuiteParserImpl parser = new CipherSuiteParserImpl();

    public CipherSuiteFilterImpl(final List<Step<CipherSuite>> steps) {
        super(steps);
    }

    @Override
    protected Set<CipherSuite> parse(final List<String> items) {
        return this.parser.parse(items);
    }

    @Override
    protected String[] getItems(final SSLParameters parameters) {
        return parameters.getCipherSuites();
    }

    @Override
    protected String[] getDefaults(final SSLEngine engine) {
        return engine.getEnabledCipherSuites();
    }

    @Override
    protected String[] getSupported(final SSLEngine engine) {
        return engine.getSupportedCipherSuites();
    }
}
