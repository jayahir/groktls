package org.archie.groktls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.archie.groktls.ItemFilter.FilterResult;
import org.archie.groktls.cipher.CipherSuite;
import org.archie.groktls.cipher.CipherSuiteFilters;
import org.archie.groktls.protocol.ProtocolVariant;
import org.archie.groktls.protocol.ProtocolVariantFilters;

/**
 * Interactive tester for cipher suite and protocol variant filter specifications.
 * <p>
 * Run without arguments, cipher suite filter specs can be entered, and the results of evaluating the filters against the cipher suites
 * supported by the JVM running the program are displayed.
 * <p>
 * When run with an argument of <code>protocolvariant</code> or <code>pv</code>, the same interactive testing can be done for protocol
 * variants.
 */
public class InteractiveFilterSpecTester {

    private static final String CS_OUTPUT_FORMAT = "%-40s %-8s %-8s %-10s %-4s %3d (%-3d) %-6s %4d %s%n";
    private static final String PV_OUTPUT_FORMAT = "%-20s %-8s %-5d %-5d %-6s %s%n";

    public static void main(final String[] args) throws NoSuchAlgorithmException, IOException, KeyManagementException {

        final boolean cs = (args.length == 0) || (!args[0].startsWith("proto") && !args[0].startsWith("pv"));

        final SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[0], null);

        final GrokTLS g = new GrokTLS();
        final ItemFilterSpecParser<?> sp = cs ? g.createCipherSuiteFilterSpecParser() : g.createProtocolVariantFilterSpecParser();

        final BufferedReader con = new BufferedReader(new InputStreamReader(System.in));

        System.out.printf("Interactive %s filter spec tester.%n", cs ? "cipher suite" : "protocol variant");
        System.out.println("Enter a blank line to exit.");
        System.out.print("> ");
        String input = con.readLine();
        while (input != null) {
            if (input.length() == 0) {
                return;
            }
            try {
                final ItemFilter<?> filter = sp.parse(input);
                final FilterResult<?> result = filter.filter(ctx);
                dump(cs, result);
            } catch (final IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }
            System.out.println();
            System.out.print("> ");
            input = con.readLine();
        }
    }

    @SuppressWarnings("unchecked")
    private static void dump(final boolean cs, final FilterResult<?> result) {
        System.out.printf("%d matches, %d excluded, %d blacklisted. %n", result.getIncluded().size(), result.getExcluded().size(), result
                .getBlacklisted().size());
        if (result.getIncluded().isEmpty()) {
            return;
        }

        if (cs) {
            dumpCipherSuites((FilterResult<CipherSuite>) result);
        } else {
            dumpProtocolVariants((FilterResult<ProtocolVariant>) result);
        }
    }

    private static void dumpProtocolVariants(final FilterResult<ProtocolVariant> result) {
        System.out.printf("%-20s %-8s %-5s %-3s %-6s %s%n", "Variant", "Family", "Major", "Minor", "Pseudo", "Unsafe");
        for (final ProtocolVariant c : result.getIncluded()) {
            System.out.printf(PV_OUTPUT_FORMAT,
                              c.getName(),
                              c.getFamily(),
                              c.getMajorVersion(),
                              c.getMinorVersion(),
                              c.getPseudoProtocol() == null ? "" : c.getPseudoProtocol(),
                              ProtocolVariantFilters.isSafe(c) ? "" : "*");
        }
    }

    private static void dumpCipherSuites(final FilterResult<CipherSuite> result) {
        System.out.printf("%-40s %-8s %-8s %-10s %-4s %3s %-3s   %-6s %4s %s%n",
                          "Cipher",
                          "Kx",
                          "Au",
                          "Enc",
                          "Mode",
                          "Key",
                          "Str",
                          "Mac",
                          "Size",
                          "Unsafe");

        for (final CipherSuite c : result.getIncluded()) {
            if (c.isSignalling()) {
                System.out.println(c.getName());
            } else {
                System.out.printf(CS_OUTPUT_FORMAT, c.getName(), c.getKeyExchange().getKeyAgreementAlgo(), c.getKeyExchange()
                        .getAuthenticationAlgo(), c.getCipher().getAlgorithm(), c.getCipher().getMode() == null ? "" : c.getCipher()
                        .getMode(), c.getCipher().getKeySize(), c.getCipher().getStrength(), c.getMac().getAlgorithm(), c.getMac()
                        .getSize(), CipherSuiteFilters.isSafe(c) ? "" : "*");
            }
        }
    }
}
