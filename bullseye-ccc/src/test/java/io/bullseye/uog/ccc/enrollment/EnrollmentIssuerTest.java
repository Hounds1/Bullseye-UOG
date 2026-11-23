package io.bullseye.uog.ccc.enrollment;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;

class EnrollmentIssuerTest {
    private static final String ISSUER_ALIAS = "core-ca";
    private static final char[] PASSWORD = "fixture-only".toCharArray();
    private static final X500Name ROOT = new X500Name("CN=Enrollment Root");
    private static final X500Name INTERMEDIATE = new X500Name("CN=Enrollment Issuer");

    @TempDir Path directory;

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC"})
    void issuesOnlyAnApprovedCoreClientIdentity(String issuerAlgorithm) throws Exception {
        KeyPair authorityKey = keyPair(issuerAlgorithm);
        Instant expiry = Instant.now().plus(Duration.ofDays(120));
        X509Certificate authority = authority(
                ROOT, ROOT, authorityKey.getPublic(), authorityKey.getPrivate(), expiry, true);
        Path store = keyStore(authorityKey, authority);
        var issuer = new EnrollmentIssuer(store, PASSWORD, ISSUER_ALIAS);
        KeyPair clientKey = keyPair("EC");
        String approved = "#abcd, OU=ignored";
        String request = csr(clientKey.getPublic(), clientKey.getPrivate());
        if ("RSA".equals(issuerAlgorithm)) {
            request = request.replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST");
        }

        var verified = EnrollmentIssuer.verifyCsr(request);
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(clientKey.getPublic().getEncoded())), verified.publicKeySha256());
        var issued = issuer.issue(approved, verified);
        List<X509Certificate> chain = parseChain(issued.chainPem());
        X509Certificate leaf = chain.getFirst();
        assertEquals(2, chain.size());
        assertEquals(authority, chain.getLast());
        leaf.verify(authority.getPublicKey());
        leaf.checkValidity();

        var subject = X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded());
        assertEquals(1, subject.getRDNs().length);
        assertEquals(approved, ((ASN1String) subject.getRDNs(BCStyle.CN)[0].getFirst().getValue()).getString());
        assertArrayEquals(clientKey.getPublic().getEncoded(), leaf.getPublicKey().getEncoded());
        assertEquals(-1, leaf.getBasicConstraints());
        assertTrue(leaf.getKeyUsage()[0]);
        assertEquals(List.of(KeyPurposeId.id_kp_clientAuth.getId()), leaf.getExtendedKeyUsage());
        assertNull(leaf.getSubjectAlternativeNames());
        assertEquals(Duration.ofDays(90),
                Duration.between(leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant()));
        assertEquals(HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded())), issued.fingerprint());
        assertNotEquals(leaf.getSerialNumber(), parseChain(issuer.issue(approved, verified).chainPem())
                .getFirst().getSerialNumber());
    }

    @Test
    void capsLeafValidityAtEarliestExpiryInIssuerChain() throws Exception {
        KeyPair root = keyPair("EC");
        KeyPair intermediate = keyPair("EC");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresFirst = now.plus(Duration.ofDays(2));
        X509Certificate rootCertificate = authority(
                ROOT, ROOT, root.getPublic(), root.getPrivate(), expiresFirst, true);
        X509Certificate issuerCertificate = authority(INTERMEDIATE, ROOT, intermediate.getPublic(),
                root.getPrivate(), now.plus(Duration.ofDays(5)), true);
        var issuer = new EnrollmentIssuer(
                keyStore(intermediate, issuerCertificate, rootCertificate), PASSWORD, ISSUER_ALIAS);
        KeyPair client = keyPair("EC");

        var verified = EnrollmentIssuer.verifyCsr(csr(client.getPublic(), client.getPrivate()));
        List<X509Certificate> chain = parseChain(issuer.issue("edge-42", verified).chainPem());
        assertEquals(3, chain.size());
        assertEquals(expiresFirst, chain.getFirst().getNotAfter().toInstant());
        assertEquals(issuerCertificate, chain.get(1));
        assertEquals(rootCertificate, chain.getLast());
    }

    @Test
    void rejectsWrongKeyProofUnsupportedCurvesAndMultipleRequests() throws Exception {
        KeyPair client = keyPair("EC");
        String valid = csr(client.getPublic(), client.getPrivate());
        String wrongSignature = csr(client.getPublic(), keyPair("EC").getPrivate());
        KeyPair alternateCurve = curveKeyPair("secp384r1");
        String unsupported = csr(alternateCurve.getPublic(), alternateCurve.getPrivate());

        assertThrows(IllegalArgumentException.class, () -> EnrollmentIssuer.verifyCsr(wrongSignature));
        assertThrows(IllegalArgumentException.class, () -> EnrollmentIssuer.verifyCsr(unsupported));
        assertThrows(IllegalArgumentException.class, () -> EnrollmentIssuer.verifyCsr(valid + valid));
        assertThrows(IllegalArgumentException.class, () -> EnrollmentIssuer.verifyCsr(valid + "trailing data"));
    }

    @Test
    void rejectsAnIssuerWithoutCaPermission() throws Exception {
        KeyPair key = keyPair("EC");
        X509Certificate endEntity = authority(
                ROOT, ROOT, key.getPublic(), key.getPrivate(), Instant.now().plus(Duration.ofDays(120)), false);
        Path store = keyStore(key, endEntity);

        assertThrows(IOException.class, () -> new EnrollmentIssuer(store, PASSWORD, ISSUER_ALIAS));
    }

    private Path keyStore(KeyPair key, X509Certificate... chain) throws Exception {
        Path file = directory.resolve("issuer.p12");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, PASSWORD);
        store.setKeyEntry(ISSUER_ALIAS, key.getPrivate(), PASSWORD, chain);
        try (var output = Files.newOutputStream(file)) {
            store.store(output, PASSWORD);
        }
        return file;
    }

    private static X509Certificate authority(X500Name subject, X500Name issuer, PublicKey publicKey,
            PrivateKey issuerKey, Instant expiry, boolean ca) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(ca ? 1 : 2),
                Date.from(Instant.now().minus(Duration.ofDays(1))), Date.from(expiry), subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        String algorithm = "RSA".equals(issuerKey.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
        var signer = new JcaContentSignerBuilder(algorithm).build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static KeyPair keyPair(String algorithm) throws Exception {
        if ("EC".equals(algorithm)) {
            return curveKeyPair("secp256r1");
        }
        var generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyPair curveKeyPair(String namedCurve) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(namedCurve));
        return generator.generateKeyPair();
    }

    private static String csr(PublicKey publicKey, PrivateKey signerKey) throws Exception {
        var requestedExtensions = new ExtensionsGenerator();
        requestedExtensions.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        requestedExtensions.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        var builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=untrusted request"), publicKey);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, requestedExtensions.generate());
        var signed = builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signerKey));
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(signed.getEncoded())
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    private static List<X509Certificate> parseChain(String pem) throws Exception {
        return CertificateFactory.getInstance("X.509").generateCertificates(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))).stream()
                .map(X509Certificate.class::cast).toList();
    }
}
