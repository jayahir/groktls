package org.archie.groktls;

import java.util.Comparator;

import org.archie.groktls.ItemFilterBuilder.Filter;
import org.archie.groktls.cipher.CipherSuiteFilters;
import org.archie.groktls.protocol.ProtocolVariantFilters;

/**
 * A parser for filter specifications that describe a series of steps
 * 
 * <p>
 * <h4>General Overview</h4>
 * The filter specifications parsed by this parser generally follow the approach and syntax of the <a
 * href="http://www.openssl.org/docs/apps/ciphers.html">OpenSSL ciphers</a> command.
 * <p>
 * Item filters are built up as a sequence of parts separated by <code>:</code> or <code>,<code> characters, with each part being one of
 * the operations supported by {@link ItemFilterBuilder} applied to an expression that corresponds to a filter over the items to be matched.
 * <p>
 * 
 * <h4>Operations</h4>
 * The available operations are:
 * <ul>
 * <li>Items without prefixes are {@link ItemFilterBuilder#add(Filter) inclusions}.</li>
 * <li>Items prefixed by a <code>-</code> are {@link #delete(Filter) exclusions}.</li>
 * <li>Items prefixed by a <code>!<code> are {@link #blacklist(Filter) blacklist} operations.</li>
 * <li>Items prefixed by a <code>@</code> are {@link #sort(Comparator) sort} operations</li> </ul>
 * 
 * Additionally, each part can be made up of individual filters concatenated with a <code>+</code>, representing a logical <code>and</code>
 * over the individual filters to produce a single filter that is used with the specified operation in that step.
 * <p>
 * <h4>Filters</h4>
 * After removing the operation prefix, and splitting concatenated (<code>+</code>) filters, the filter expressions that can be used are
 * implementation specific, although all implementations will provide the following filter aliases:
 * <ul>
 * <li><b>SUPPORTED</b> - matches all of the supported items, including <b><em>unsafe</em></b> items.</li>
 * <li><b>ALL</b> - matches all of the <em>safe</em> supported items.</li>
 * <li><b>COMPLEMENTALL/UNSAFE</b>- matches all of the <b><em>unssafe</em></b> items in the <code>SUPPORTED</code> set, i.e. those not in
 * <code>ALL</code>.</li>
 * <li><b>DEFAULT</b> - matches all of the <em>safe</em> default items.</li>
 * <li><b>COMPLEMENTDEFAULT</b> - matches all of the <em>safe</em> items in <code>ALL</code> that are not in the default set.</li>
 *
 * </ul>
 *
 * <br>
 * For more information, see the documentation for individual methods in {@link CipherSuiteFilters} and {@link ProtocolVariantFilters}.
 * <p>
 * <h4>Usage Examples</h4>
 *
 * Match all (safe) cipher suites using <code>AES</code> encryption, remove any using <code>SHA</code>, then sort the remaining items by
 * effective key strength:
 *
 * <pre>
 * new GrokTLS().createCipherSuiteFilterSpecParser().parse(&quot;eAES:-mSHA:@STRENGTH&quot;);
 * </pre>
 */
public interface ItemFilterSpecParser<I extends NamedItem> {

    ItemFilter<I> parse(String filterSpec);

}
