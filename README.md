GrokTLS
----

A Java library for parsing TLS cipher suite and protocol variant names and filtering them using simple builder syntax or OpenSSL like filter expressions.

## Features

- Parsing of SSL and TLS cipher suite names and protocol version names on all Java platforms
- Smart parsing handles current and future cipher suite names, including non-standard names on IBM Java VMs
- Criteria based filtering of cipher suites and protocol versions using a fluent builder syntax
- OpenSSL like filter syntax, allowing configuration of filters in applications
- Filter syntax is compatible with lists of cipher suite names, allowing drop-in enhancement of existing applications
- Filtering excludes unsafe cipher suites (including export cipher suites) by default, avoiding mistakes
- Interactive tester application to determine Java VM capabilities and test filters
- Packaged as an OSGi bundle

## Licensing

GrokTLS is released under the [The Apache Software License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

## Downloading

...

## Usage

### Unsafe Cipher Suites

By default GrokTLS excludes unsafe cipher suites and protocol variants, and unless you explicitly include them they aren't matched by filter rules, with the exception of filter rules explicitly notes as matching unsafe filters (such as `SUPPORTED`).
The exception to this rule is that unsafe items that have already been matched in a filter will be matched by subsequent safe filters.

Unsafe cipher suites are those that have:
* `NULL` encryption
* `NULL` key exchange
* `NULL` or `anon` authentication
* `NULL` mac/digest
* `EXPORT` grade key exchange or encryption

Unsafe protocol variants are `SSLv2` and below.

### Parsing

```java
CipherSuite cs = new GrokTLS().createCipherSuiteParser().parse("TLS_DHE_DSS_WITH_RC4_128_SHA");
```

```java
ProtocolVariant pv = new GrokTLS().createProtocolVariantParser().parse("TLSv1.2");
```

### Filtering with Builder Syntax

```java
import static org.archie.groktls.protocol.CipherSuiteFilters.*;
...

ItemFilterBuilder<CipherSuite> csBuilder = new GrokTLS().createCipherSuiteFilterBuilder();
ItemFilter<CipherSuite> csFilter = csBuilder.add(fips()).sort(byEncryptionStrength()).build();
SSLContext context = SSLContext.getInstance("TLS");
context.init(...);
String[] ciphers = csFilter.filter(sslContext).getIncludedNames();
```

```java
ItemFilterBuilder<ProtocolVariant> pvBuilder = new GrokTLS().createProtocolVariantFilterBuilder();
ItemFilter<ProtocolVariant> pvFilter = pvBuilder.add(minimumVersion("TLSv1")).build();
SSLContext context = SSLContext.getInstance("TLS");
context.init(...);
String[] protocols = pvFilter.filter(sslContext).getIncludedNames();
```

### Filtering with Filter Syntax

```java
ItemFilterSpecParser<CipherSuite> parser = new GrokTLS().createCipherSuiteFilterSpecParser();
ItemFilter<CipherSuite> csFilter = parser.parse("FIPS:@STRENGTH");
SSLContext context = SSLContext.getInstance("TLS");
context.init(...);
String[] ciphers = csFilter.filter(sslContext).getIncludedNames();
```

```java
ItemFilterSpecParser<CipherSuite> parser = new GrokTLS().createProtocolVariantFilterSpecParser();
ItemFilter<ProtocolVariant> pvFilter = parser.parse(">=TLSv1");
SSLContext context = SSLContext.getInstance("TLS");
context.init(...);
String[] protocols = pvFilter.filter(sslContext).getIncludedNames();
```

## Filter Syntax

### High Level Syntax

Filters consist of one or more parts, separated by a `:` or `,`.
Each part is either a single filter expression, or a concatenation of multiple filter expressions (a logical _and_ operation) using a `+`.
Parts are of the following types, distinguished by a prefix character:
* (no prefix) - add matched items. Items already matched remain in the place they were matched, new items are added to the end.
* `+` - add matched items. Items already matched are removed from the order and added again at the end.
* `-` - remove matched items. Items may be re-added by subsequent filter parts.
* `!` - remove matched items and blacklist them. Items will not be re-added, even if matched by subsequent filter parts.

e.g.:
* `EXPR1:EXPR2` - all items matching `EXPR1`, followed by items matching `EXPR2`
* `EXPR1+EXPR2` - all items matching `EXPR1` and `EXPR2`
* `EXPR1:+EXPR2` - all items matching `EXPR1`, with any items matching `EXPR2` moved to the end of the list
* `EXPR1:-EXPR2` - all items matching `EXPR1`, except the items matching `EXPR2`
* `EXPR1:!EXPR2:EXPR3` - all items matching `EXPR1`, except the items matching `EXPR2`, followed by items matching `EXPR3` that are not matched by `EXPR2`

### Common Filters

* `SUPPORTED` - matches all supported cipher suites, including unsafe cipher suites
* `ALL` - matches all safe supported cipher suites
* `COMPLEMENTOFALL`/`UNSAFE` - matches all supported cipher suites not matched by `ALL`
* `DEFAULT` - matches all safe default cipher suites
* `COMPLEMENTOFDEFAULT` - matches all safe supported cipher suites (e.g. `ALL`) not matched by `DEFAULT`

### Cipher Suite Filters

* `FIPS` or `FIPS140` - matches cipher suites using only approved (or generally accepted) for use in FIP 140-2:
  * `DH`, `DHE`, `RSA`, `ECDH` and `ECDHE` key exchange
  * `DSS`, `RSA`, `ECDSA` authentication
  * `AES` and `3DES` encryption
  * `CBC` and `GCM` encryption modes
  * `SHA`, `SHA256` and `SHA384` mac/digest
* `SCSV` - matches any signalling cipher suite values (e.g. `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`)
* `HIGH` - matches cipher suites with strong encryption - currently `AES` >= 128 bit encryption and any other algorithm with key length > 128 bits
* `MEDIUM` - matches cipher suites using medium strength encryption - currently any 128 bit encryption algorithm other than `AES`
* `LOW` - matches cipher suites using low strength encryption - currently any encryption algorithm with < 128 bit key length
* `EXPORT` or `EXP` - matches cipher suites with export weakened key exchange or encryption. Will not match anything unless `UNSAFE` is also used.
* `SUITEB128` - matches cipher suites using algorithms approved for use in TLS by NSA Suite B with a 128 bit minimum security
* `SUITEB192` - matches cipher suites using algorithms approved for use in TLS by NSA Suite B with a 192 bit minimum security
* `CIPHER_SUITE_NAME` - e.g. `TLS_DHE_DSS_WITH_RC4_128_SHA` - matches a specific cipher suite
* `kALGO` - e.g. `kECDHE` - matches cipher suites using the specified key exchange algorithm
* `aALGO` - e.g. `aDSS` - matches cipher suites using the specified authentication algorithm
* `mALGO` - e.g. `mSHA` - matches cipher suites using the specified digest/mac algorithm
* `eALGO` - e.g. `eAES` - matches cipher suites using the specified encryption algorithm
* `eALGO_LEN` - e.g. `eAES_128` - matches cipher suites using the specified encryption algorithm with at least the specified key length
* `eALGO_LEN_MODE` - e.g. `eAES_128_GCM` - matches cipher suites using the specified encryption algorithm and mode with at least the specified key length
* `e_LEN` - e.g. `e_128` - matches cipher suites using the any encryption algorithm with at least the specified key length
* `e_MODE` - e.g. `e_GCM` - matches cipher suites using the specified encryption mode
* `e_LEN_MODE` - e.g. `e_128_GCM` - matches cipher suites using the any encryption algorithm in the specified mode with at least the specified key length

### Cipher Suite Orderings

* `@STRENGTH` - orders matched cipher suites by the effective key length (taking into account known vulnerabilities)
* `@LENGTH` - orders matched cipher suites by the key length

All filter expressions that take an algorithm accept the value `NULL` to match cipher suites with `NULL` or `anon` values.

### Protocol Variant Filters

* `fFAMILY` - e.g. `fTLS` - matches any protocol variant in the specified family
* `>=PROTOCOL` - e.g. `>=TLSv1.1` - matches any protocol variant >= the specified variant
* `PSEUDO` - matches any pseudo protocols (e.g. `SSLv2Hello`)

## Filter Examples

### At least TLSv1

**Filter Syntax**
```java
new GrokTLS().createProtocolVariantFilterSpecParser().parse(">=TLSv1");
```

**Builder Syntax**
```java
new GrokTLS().createProtocolVariantFilterBuilder().add(minimumVersion("TLSv1")).build();
```

### FIPS compliant cipher suites, sorted by cipher strength

**Filter Syntax**
```java
new GrokTLS().createCipherSuiteFilterSpecParser().parse("FIPS:@STRENGTH");
```

**Builder Syntax**
```java
new GrokTLS().createCipherSuiteFilterBuilder().add(fips()).sort(byEncryptionStrength()).build();
```

### RC4 ciphers

**Filter Syntax**
```java
new GrokTLS().createCipherSuiteFilterSpecParser().parse("eRC4");
```

**Builder Syntax**
```java
new GrokTLS().createCipherSuiteFilterBuilder().add(encryption("RC4")).build();
```

### AES ciphers, RSA authentication last

**Filter Syntax**
```java
new GrokTLS().createCipherSuiteFilterSpecParser().parse("eAES:+aRSA");
```

**Builder Syntax**
```java
new GrokTLS().createCipherSuiteFilterBuilder().add(encryption("AES)).end(authentication("RSA")).build();
```

### Unsafe cipher suite

**Filter Syntax**
```java
new GrokTLS().createCipherSuiteFilterSpecParser().parse("UNSAFE+SSL_RSA_EXPORT_WITH_RC4_40_MD5");
```

**Builder Syntax**
```java
new GrokTLS().createCipherSuiteFilterBuilder()
             .add(and(
                  supportedIncludingUnsafe(),
                  cipherSuite("kRSA:UNSAFE+SSL_RSA_EXPORT_WITH_RC4_40_MD5")))
             .build();
```
