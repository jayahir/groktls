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

import org.archie.groktls.ItemFilter;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.impl.filter.ItemFilterBuilderImpl;
import org.archie.groktls.impl.filter.ItemFilterImpl.Step;
import org.archie.groktls.impl.filter.ItemFilterStep.Op;

public class CipherSuiteFilterBuilderImpl extends ItemFilterBuilderImpl<CipherSuite> {

    @Override
    public ItemFilter<CipherSuite> build() {
        return new CipherSuiteFilterImpl(getSteps());
    }

    @Override
    protected Step<CipherSuite> createStep(final Op op, final Filter<CipherSuite> filter) {
        return new CipherSuiteFilterStep(op, filter);
    }
}
