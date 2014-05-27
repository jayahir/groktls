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
package org.archie.groktls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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

    private boolean ciphers = true;
    private boolean client = true;
    private String engine;
    private String provider;

    private SSLContext ctx;
    private final GrokTLS grok = new GrokTLS();

    private InteractiveFilterSpecTester() {
        try {
            this.provider = SSLContext.getDefault().getProvider().getName();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to detect default SSLContext provider", e);
        }
    }

    private void start() throws NoSuchAlgorithmException, KeyManagementException {
        checkUnrestrictedJce();
        init();
    }

    /**
     * Check whether unrestricted JCE policy is installed, which will have an effect on which ciphersuites are provided (at least by the
     * SunJSSE provider).
     */
    private void checkUnrestrictedJce() {
        try {
            int maxKeyLength = Cipher.getMaxAllowedKeyLength("RC5");
            if (maxKeyLength != Integer.MAX_VALUE) {
                System.out.printf("! Unrestricted JCE policy files are not installed.%n");
                System.out.printf("! Cipher suites may be limited to <= %d bit security (<= %d bit digest/mac).%n%n",
                                  maxKeyLength,
                                  (maxKeyLength * 2));
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.printf("Failed to check unrestricted JCE: %s%n", e.getMessage());
        }
    }

    protected void init() throws KeyManagementException {
        try {
            if ((this.engine == null) || this.engine.trim().isEmpty() || this.engine.equalsIgnoreCase("default")) {
                this.ctx = SSLContext.getDefault();
            } else {
                this.ctx = SSLContext.getInstance(this.engine, this.provider);
                this.ctx.init(null, null, null);
            }
        } catch (NoSuchProviderException e) {
            System.err.printf("Provider %s is not registered%n", this.provider);
        } catch (NoSuchAlgorithmException e) {
            System.err.printf("Engine %s is not registered%n", this.engine);
        }
    }

    private void readAndProcessInput() throws IOException, KeyManagementException, NoSuchAlgorithmException {
        final BufferedReader con = new BufferedReader(new InputStreamReader(System.in));

        printStatus();
        System.out.println("Enter a blank line to exit.");
        System.out.print("> ");
        String input = con.readLine();
        while (input != null) {
            if (input.length() == 0) {
                return;
            }

            processInput(input, true);

            System.out.println();
            System.out.print("> ");
            input = con.readLine();
        }
    }

    private void processInput(final String input, final boolean status) throws KeyManagementException, NoSuchAlgorithmException {
        if ("server".equals(input)) {
            this.client = false;
            if (status) {
                printStatus();
            }
        } else if ("client".equals(input)) {
            this.client = true;
            if (status) {
                printStatus();
            }
        } else if (input.startsWith("proto") || "pv".equals(input)) {
            this.ciphers = false;
            if (status) {
                printStatus();
            }
        } else if ("cipher".equals(input) || "cs".equals(input)) {
            this.ciphers = true;
            if (status) {
                printStatus();
            }
        } else if ("consistent".equals(input)) {
            checkConsistency();
        } else if (input.startsWith("engine")) {
            this.engine = input.substring("engine".length()).trim();
            init();
            if (status) {
                printStatus();
            }
        } else if (input.startsWith("provider")) {
            this.provider = input.substring("provider".length()).trim();
            init();
            if (status) {
                printStatus();
            }
        } else {
            try {
                final ItemFilterSpecParser<?> sp = this.ciphers ? this.grok.createCipherSuiteFilterSpecParser() : this.grok
                        .createProtocolVariantFilterSpecParser();
                final ItemFilter<?> filter = sp.parse(input);
                final FilterResult<?> result = this.client ? filter.filter(this.ctx) : filter.filterServer(this.ctx);
                dump(result);
            } catch (final IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private void printStatus() {
        System.out.printf("Interactive filter spec tester [%s/%s, %s, %s].%n",
                          this.ctx.getProvider().getName(),
                          this.ctx.getProtocol(),
                          this.client ? "client" : "server",
                          this.ciphers ? "cipher suite" : "protocol variant");
    }

    public static void main(final String[] args) throws NoSuchAlgorithmException, IOException, KeyManagementException {

        InteractiveFilterSpecTester tst = new InteractiveFilterSpecTester();
        tst.start();

        boolean exit = false;
        for (String arg : args) {
            if (arg.equals("-e")) {
                exit = true;
                continue;
            }
            tst.processInput(arg, false);
        }

        if (!exit) {
            tst.readAndProcessInput();
        }
    }

    private static void checkConsistency() {
        try {
            final Set<String> protocols = new HashSet<String>();
            protocols.addAll(Arrays.asList(SSLContext.getDefault().getSupportedSSLParameters().getProtocols()));
            protocols.add("TLS");
            protocols.add("SSL");
            protocols.add("Default");

            final List<Case> protocolCases = new ArrayList<Case>();
            final List<Case> cipherCases = new ArrayList<Case>();
            for (String proto : protocols) {
                try {
                    final SSLContext ctx;
                    if ("Default".equals(proto)) {
                        ctx = SSLContext.getDefault();
                    } else {
                        ctx = SSLContext.getInstance(proto);
                        ctx.init(null, null, null);
                    }

                    ContextCases cases = getContextCases(proto, ctx);
                    cipherCases.addAll(cases.getCipherCases());
                    protocolCases.addAll(cases.getProtoCases());
                } catch (NoSuchAlgorithmException e) {
                    // Continue
                }
            }
            ContextCases cases = getDefaultCases();
            cipherCases.addAll(cases.getCipherCases());
            protocolCases.addAll(cases.getProtoCases());

            compare("Cipher Suites", cipherCases);
            System.out.println("=================================================================");
            System.out.println();
            compare("Protocol Variants", protocolCases);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static class Name implements Comparable<Name> {

        private final String protocol;
        private final String name;

        private Name(final String protocol, final String name) {
            this.protocol = protocol;
            this.name = name;
        }

        public String getProtocol() {
            return this.protocol;
        }

        public String getName() {
            return this.name;
        }

        @Override
        public int compareTo(final Name o) {
            int proto = this.protocol.compareTo(o.protocol);
            return (proto == 0) ? this.name.compareTo(o.name) : proto;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = (prime * result) + ((this.name == null) ? 0 : this.name.hashCode());
            result = (prime * result) + ((this.protocol == null) ? 0 : this.protocol.hashCode());
            return result;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            Name other = (Name) obj;
            if (this.name == null) {
                if (other.name != null) {
                    return false;
                }
            } else if (!this.name.equals(other.name)) {
                return false;
            }
            if (this.protocol == null) {
                if (other.protocol != null) {
                    return false;
                }
            } else if (!this.protocol.equals(other.protocol)) {
                return false;
            }
            return true;
        }

        @Override
        public String toString() {
            return String.format("%s - %s", this.protocol, this.name);
        }

    }

    private static class ContextCases {

        private final List<Case> protoCases;
        private final List<Case> cipherCases;

        public ContextCases(final List<Case> cipherCases, final List<Case> protoCases) {
            this.cipherCases = cipherCases;
            this.protoCases = protoCases;
        }

        public List<Case> getCipherCases() {
            return this.cipherCases;
        }

        public List<Case> getProtoCases() {
            return this.protoCases;
        }
    }

    private static class Case {

        private final String[] items;
        private final Name name;

        private Case(final String protocol, final String name, final String[] items) {
            this.name = new Name(protocol, name);
            this.items = items;
        }

        public Name getName() {
            return this.name;
        }

        public String[] getItems() {
            return this.items;
        }
    }

    private static ContextCases getDefaultCases() throws Exception {
        List<Case> cipherCases = new ArrayList<Case>();
        List<Case> protoCases = new ArrayList<Case>();

        SSLServerSocketFactory defaultServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        cipherCases.add(new Case("Default", "Default Ciphers from Default Server Socket Factory", defaultServerSocketFactory
                .getDefaultCipherSuites()));
        cipherCases.add(new Case("Default", "Supported Ciphers from Default Server Socket Factory ", defaultServerSocketFactory
                .getSupportedCipherSuites()));

        SSLServerSocket serverSocketFromDefault = (SSLServerSocket) defaultServerSocketFactory.createServerSocket();
        cipherCases
                .add(new Case("Default", "Enabled Ciphers from Default Server Socket", serverSocketFromDefault.getEnabledCipherSuites()));
        cipherCases.add(new Case("Default", "Supported Ciphers from Default Server Socket", serverSocketFromDefault
                .getSupportedCipherSuites()));

        protoCases.add(new Case("Default", "Enabled Protocols from Default Server Socket", serverSocketFromDefault.getEnabledProtocols()));
        protoCases.add(new Case("Default", "Supported Protocols from Default Server Socket", serverSocketFromDefault
                .getSupportedProtocols()));

        SSLSocketFactory defaultSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        cipherCases.add(new Case("Default", "Default Ciphers from Default Socket Factory", defaultSocketFactory.getDefaultCipherSuites()));
        cipherCases.add(new Case("Default", "Supported Ciphers from Default Socket Factory", defaultSocketFactory
                .getSupportedCipherSuites()));

        SSLSocket socketFromDefaultFactory = (SSLSocket) defaultSocketFactory.createSocket();
        cipherCases.add(new Case("Default", "Enabled Ciphers from Default Socket", socketFromDefaultFactory.getEnabledCipherSuites()));
        cipherCases.add(new Case("Default", "Supported Ciphers from Default Socket", socketFromDefaultFactory.getSupportedCipherSuites()));
        cipherCases.add(new Case("Default", "Enabled Ciphers from Default Socket Parameters", socketFromDefaultFactory.getSSLParameters()
                .getCipherSuites()));

        protoCases.add(new Case("Default", "Enabled Protocols from Default Socket", socketFromDefaultFactory.getEnabledProtocols()));
        protoCases.add(new Case("Default", "Supported Protocols from Default Socket", socketFromDefaultFactory.getEnabledProtocols()));
        protoCases.add(new Case("Default", "Enabled Protocols from Default Socket Parameters", socketFromDefaultFactory
                .getEnabledProtocols()));

        return new ContextCases(cipherCases, protoCases);
    }

    private static ContextCases getContextCases(final String protocol, final SSLContext ctx) throws Exception {
        List<Case> cc = new ArrayList<Case>();
        List<Case> pc = new ArrayList<Case>();

        SSLEngine serverEngine = ctx.createSSLEngine();
        serverEngine.setUseClientMode(false);
        SSLEngine clientEngine = ctx.createSSLEngine();
        clientEngine.setUseClientMode(true);

        SSLServerSocketFactory serverSocketFactoryFromContext = ctx.getServerSocketFactory();
        SSLSocketFactory socketFactoryFromContext = ctx.getSocketFactory();

        SSLParameters defaultParamsFromContext = ctx.getDefaultSSLParameters();
        SSLParameters supportedParamsFromContext = ctx.getSupportedSSLParameters();

        cc.add(new Case(protocol, "Enabled Ciphers from Server Engine", serverEngine.getEnabledCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Server Engine", serverEngine.getSupportedCipherSuites()));
        cc.add(new Case(protocol, "Enabled Ciphers from Server Engine Parameters", serverEngine.getSSLParameters().getCipherSuites()));

        pc.add(new Case(protocol, "Enabled Protocols from Server Engine", serverEngine.getEnabledProtocols()));
        pc.add(new Case(protocol, "Supported Protocols from Server Engine", serverEngine.getSupportedProtocols()));
        pc.add(new Case(protocol, "Enabled Protocols from Server Engine Parameters", serverEngine.getSSLParameters().getProtocols()));

        cc.add(new Case(protocol, "Enabled Ciphers from Client Engine", clientEngine.getEnabledCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Client Engine", clientEngine.getSupportedCipherSuites()));
        cc.add(new Case(protocol, "Enabled Ciphers from Client Engine Parameters", clientEngine.getSSLParameters().getCipherSuites()));

        pc.add(new Case(protocol, "Enabled Protocols from Client Engine", clientEngine.getEnabledProtocols()));
        pc.add(new Case(protocol, "Supported Protocols from Client Engine", clientEngine.getSupportedProtocols()));
        pc.add(new Case(protocol, "Enabled Protocols from Client Engine Parameters", clientEngine.getSSLParameters().getProtocols()));

        cc.add(new Case(protocol, "Default Ciphers from Context Parameters", defaultParamsFromContext.getCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Context Parameters", supportedParamsFromContext.getCipherSuites()));

        pc.add(new Case(protocol, "Default Protocols from Context", defaultParamsFromContext.getProtocols()));
        pc.add(new Case(protocol, "Supported Protocols from Context", supportedParamsFromContext.getProtocols()));

        cc.add(new Case(protocol, "Default Ciphers from Context Server Socket Factory", serverSocketFactoryFromContext
                .getDefaultCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Context Server Socket Factory", serverSocketFactoryFromContext
                .getSupportedCipherSuites()));

        SSLServerSocket serverSocketFromContext = (SSLServerSocket) serverSocketFactoryFromContext.createServerSocket();

        cc.add(new Case(protocol, "Enabled Ciphers from Context Server Socket", serverSocketFromContext.getEnabledCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Context Server Socket", serverSocketFromContext.getSupportedCipherSuites()));

        cc.add(new Case(protocol, "Default Ciphers from Context Socket Factory", socketFactoryFromContext.getDefaultCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Context Socket Factory", socketFactoryFromContext.getSupportedCipherSuites()));

        pc.add(new Case(protocol, "Enabled Protocols from Context Server Socket", serverSocketFromContext.getEnabledProtocols()));
        pc.add(new Case(protocol, "Supported Protocols from Context Server Socket", serverSocketFromContext.getSupportedProtocols()));

        SSLSocket socketFromContextFactory = (SSLSocket) socketFactoryFromContext.createSocket();

        cc.add(new Case(protocol, "Enabled Ciphers from Context Socket", socketFromContextFactory.getEnabledCipherSuites()));
        cc.add(new Case(protocol, "Supported Ciphers from Context Socket", socketFromContextFactory.getSupportedCipherSuites()));
        cc.add(new Case(protocol, "Enabled Ciphers from Context Socket Parameters", socketFromContextFactory.getSSLParameters()
                .getCipherSuites()));

        pc.add(new Case(protocol, "Enabled Protocols from Context Socket", socketFromContextFactory.getEnabledProtocols()));
        pc.add(new Case(protocol, "Supported Protocols from Context Socket", socketFromContextFactory.getSupportedProtocols()));
        pc.add(new Case(protocol, "Enabled Protocols from Context Socket Parameters", socketFromContextFactory.getSSLParameters()
                .getProtocols()));

        return new ContextCases(cc, pc);
    }

    private static void compare(final String test, final List<Case> items) {
        final Set<String> superset = new TreeSet<String>();
        TreeSet<Name> uniqueNames = new TreeSet<Name>();

        for (Case item : items) {
            superset.addAll(Arrays.asList(item.getItems()));
            uniqueNames.add(item.getName());
        }

        final Set<String> commonSet = new TreeSet<String>(superset);
        for (Case item : items) {
            commonSet.retainAll(Arrays.asList(item.getItems()));
        }

        if (uniqueNames.size() != items.size()) {
            System.err.println("Duplicate names");
        }
        Map<Set<String>, Set<String>> groupedNames = groupByProtocol(uniqueNames);
        System.out.printf("Comparing %s (%d) Locations:%n", test, sum(groupedNames.values()));
        for (Entry<Set<String>, Set<String>> item : groupedNames.entrySet()) {
            System.out.printf(" %s%n", item.getKey());
            for (String name : item.getValue()) {
                System.out.printf("  %s%n", name);
            }
        }
        System.out.println();
        System.out.printf("Shared subset of items (%d):%n", commonSet.size());
        for (String item : commonSet) {
            System.out.println(" " + item);
        }
        Set<String> totalOverhang = new TreeSet<String>(superset);
        totalOverhang.removeAll(commonSet);
        System.out.println();
        System.out.printf("Total overhang (%d):%n", totalOverhang.size());
        for (String item : totalOverhang) {
            System.out.println(" " + item);
        }
        System.out.println();

        final Map<Set<String>, Set<Name>> consistents = new HashMap<Set<String>, Set<Name>>();

        // System.out.println("Individual details:");

        for (Case item : items) {
            Set<String> itemSet = new TreeSet<String>(Arrays.asList(item.getItems()));

            Set<Name> consistentWith = consistents.get(itemSet);
            if (consistentWith == null) {
                consistentWith = new TreeSet<Name>();
                consistents.put(itemSet, consistentWith);
            }
            consistentWith.add(item.getName());
        }
        System.out.println();
        System.out.printf("Consistent subsets (%d):%n", consistents.size());
        for (Entry<Set<String>, Set<Name>> consistentSubset : consistents.entrySet()) {
            Set<String> itemSet = consistentSubset.getKey();
            Set<Name> itemNames = consistentSubset.getValue();

            Map<Set<String>, Set<String>> namesByProtocol = groupByProtocol(itemNames);
            System.out.printf(" Members (%d):%n", sum(namesByProtocol.values()));
            for (Entry<Set<String>, Set<String>> entry : namesByProtocol.entrySet()) {
                System.out.printf("  %s%n", entry.getKey());
                for (String name : entry.getValue()) {
                    System.out.printf("    %s%n", name);
                }
            }
            System.out.printf(" Items (%d):%n", itemSet.size());
            for (String item : itemSet) {
                System.out.println("   " + item);
            }
            Set<String> underhang = new TreeSet<String>(superset);
            underhang.removeAll(itemSet);

            Set<String> overhang = new TreeSet<String>(itemSet);
            overhang.removeAll(commonSet);

            System.out.printf(" Underhang (%d):%n", underhang.size());
            for (String item : underhang) {
                System.out.println("   " + item);
            }
            System.out.printf(" Overhang (%d):%n", overhang.size());
            for (String item : overhang) {
                System.out.println("   " + item);
            }
            System.out.println();
        }
    }

    private static int sum(final Collection<Set<String>> values) {
        int count = 0;
        for (Set<String> set : values) {
            count += set.size();
        }
        return count;
    }

    private static Map<Set<String>, Set<String>> groupByProtocol(final Set<Name> itemNames) {
        final Map<String, Set<String>> protosByName = new TreeMap<String, Set<String>>();
        for (Name name : itemNames) {
            Set<String> names = protosByName.get(name.getName());
            if (names == null) {
                names = new TreeSet<String>();
                protosByName.put(name.getName(), names);
            }
            names.add(name.getProtocol());
        }

        Map<Set<String>, Set<String>> namesByProtoGroup = new TreeMap<Set<String>, Set<String>>(new Comparator<Set<String>>() {
            @Override
            public int compare(final Set<String> o1, final Set<String> o2) {
                return o1.toString().compareTo(o2.toString());
            }
        });
        for (Entry<String, Set<String>> entry : protosByName.entrySet()) {
            Set<String> protos = entry.getValue();
            String name = entry.getKey();
            Set<String> namesForProtos = namesByProtoGroup.get(protos);
            if (namesForProtos == null) {
                namesForProtos = new TreeSet<String>();
                namesByProtoGroup.put(protos, namesForProtos);
            }
            namesForProtos.add(name);
        }

        return namesByProtoGroup;
    }

    @SuppressWarnings("unchecked")
    private void dump(final FilterResult<?> result) {
        System.out.printf("%d matches, %d excluded, %d blacklisted. %n", result.getIncluded().size(), result.getExcluded().size(), result
                .getBlacklisted().size());
        if (result.getIncluded().isEmpty()) {
            return;
        }

        if (this.ciphers) {
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
