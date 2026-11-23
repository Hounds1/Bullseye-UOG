package io.bullseye.uog.ccc.enrollment;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Issues v1 Core client certificates using an operator-supplied PKCS12 CA key. */
public final class EnrollmentIssuer {
    private static final String CSR_LABEL = "CERTIFICATE REQUEST";
    private static final String KEYTOOL_CSR_LABEL = "NEW CERTIFICATE REQUEST";
    private static final Duration LEAF_VALIDITY = Duration.ofDays(90);
    private static final Base64.Encoder CERTIFICATE_PEM_ENCODER =
            Base64.getMimeEncoder(64, new byte[] {'\n'});

    public record Certificate(String fingerprint, String chainPem) {}

    private final PrivateKey privateKey;
    private final List<X509Certificate> issuerChain;
    private final String signatureAlgorithm;
    private final SecureRandom random = new SecureRandom();

    public EnrollmentIssuer(Path issuerKeyStore, char[] password, String alias) throws IOException {
        Objects.requireNonNull(issuerKeyStore, "issuerKeyStore");
        Objects.requireNonNull(password, "password");
        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("An issuer key alias is required");
        }
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(issuerKeyStore)) {
                store.load(input, password);
            }
            if (!(store.getKey(alias, password) instanceof PrivateKey key)) {
                throw new IOException("Issuer alias does not name a private key");
            }
            var certificates = store.getCertificateChain(alias);
            if (certificates == null || certificates.length == 0) {
                throw new IOException("Issuer alias has no certificate chain");
            }

            var chain = new ArrayList<X509Certificate>(certificates.length);
            Date now = Date.from(Instant.now());
            for (var entry : certificates) {
                if (!(entry instanceof X509Certificate certificate)) {
                    throw new IOException("Issuer chain must contain X.509 certificates");
                }
                requireCa(certificate);
                certificate.checkValidity(now);
                chain.add(certificate);
            }
            validatePath(chain, now);
            String algorithm = signatureAlgorithm(key);
            requireMatchingKey(key, chain.getFirst().getPublicKey(), algorithm);
            privateKey = key;
            issuerChain = List.copyOf(chain);
            signatureAlgorithm = algorithm;
        } catch (GeneralSecurityException failure) {
            throw new IOException("Unable to initialize the enrollment certificate issuer", failure);
        }
    }

    public Certificate issue(String nodeId, String csrPem) throws IOException {
        if (nodeId == null || nodeId.isBlank()) {
            throw new IllegalArgumentException("An approved node ID is required");
        }
        PublicKey clientKey = verifiedClientKey(csrPem);
        Instant now = Instant.now();
        Instant notBefore = now.truncatedTo(ChronoUnit.SECONDS);
        Instant notAfter = notBefore.plus(LEAF_VALIDITY);
        X509Certificate issuer = issuerChain.getFirst();
        try {
            for (X509Certificate authority : issuerChain) {
                authority.checkValidity(Date.from(now));
                Instant startsAt = authority.getNotBefore().toInstant();
                if (startsAt.isAfter(notBefore)) {
                    notBefore = startsAt;
                }
                Instant expiry = authority.getNotAfter().toInstant();
                if (expiry.isBefore(notAfter)) {
                    notAfter = expiry;
                }
            }
            if (!notAfter.isAfter(notBefore)) {
                throw new IOException("Issuer certificate chain expires before the issued certificate is valid");
            }
            // Encode the approved ID as a value so DN syntax in the ID is not interpreted.
            var subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, new DERUTF8String(nodeId)).build();
            BigInteger serial = new BigInteger(159, random).setBit(158);
            var builder = new JcaX509v3CertificateBuilder(issuer, serial,
                    Date.from(notBefore), Date.from(notAfter), subject, clientKey);
            var identifiers = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    identifiers.createSubjectKeyIdentifier(clientKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    identifiers.createAuthorityKeyIdentifier(issuer));
            var signer = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
            List<X509Certificate> chain = new ArrayList<>(issuerChain.size() + 1);
            chain.add(leaf);
            chain.addAll(issuerChain);
            validatePath(chain, Date.from(now));

            String fingerprint = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
            StringBuilder pem = new StringBuilder();
            for (X509Certificate certificate : chain) {
                pem.append("-----BEGIN CERTIFICATE-----\n")
                        .append(CERTIFICATE_PEM_ENCODER.encodeToString(certificate.getEncoded()))
                        .append("\n-----END CERTIFICATE-----\n");
            }
            return new Certificate(fingerprint, pem.toString());
        } catch (GeneralSecurityException | OperatorCreationException failure) {
            throw new IOException("Unable to sign a Core client certificate", failure);
        }
    }

    private static PublicKey verifiedClientKey(String pem) {
        try {
            var request = new PKCS10CertificationRequest(decodeRequest(pem));
            var key = request.getSubjectPublicKeyInfo().getAlgorithm();
            if (!X9ObjectIdentifiers.id_ecPublicKey.equals(key.getAlgorithm())
                    || !X9ObjectIdentifiers.prime256v1.equals(key.getParameters())
                    || !X9ObjectIdentifiers.ecdsa_with_SHA256.equals(request.getSignatureAlgorithm().getAlgorithm())) {
                throw new IllegalArgumentException("A P-256 CSR signed with ECDSA/SHA-256 is required");
            }
            PublicKey publicKey = new JcaPKCS10CertificationRequest(request).getPublicKey();
            if (!request.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey))) {
                throw new IllegalArgumentException("Invalid CSR signature");
            }
            return publicKey;
        } catch (IOException | GeneralSecurityException | OperatorCreationException | PKCSException failure) {
            throw new IllegalArgumentException("Invalid Core certificate signing request", failure);
        }
    }

    private static byte[] decodeRequest(String pem) {
        if (pem == null) {
            throw new IllegalArgumentException("A PEM certificate signing request is required");
        }
        String document = pem.strip();
        String label = document.startsWith("-----BEGIN " + KEYTOOL_CSR_LABEL + "-----")
                ? KEYTOOL_CSR_LABEL : CSR_LABEL;
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        if (!document.startsWith(begin) || !document.endsWith(end)) {
            throw new IllegalArgumentException("Expected one PEM certificate signing request");
        }
        String body = document.substring(begin.length(), document.length() - end.length());
        return Base64.getDecoder().decode(body.replaceAll("\\s", ""));
    }

    private static void requireCa(X509Certificate certificate) throws IOException {
        boolean[] keyUsage = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0
                || (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5]))) {
            throw new IOException("Issuer chain must contain CA certificates permitted to sign certificates");
        }
    }

    private static String signatureAlgorithm(PrivateKey key) throws IOException {
        return switch (key.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new IOException("Issuer private key must be RSA or EC");
        };
    }

    private static void requireMatchingKey(PrivateKey key, PublicKey certificateKey, String algorithm)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(algorithm);
        byte[] challenge = "bullseye-uog enrollment issuer key check".getBytes(StandardCharsets.US_ASCII);
        signature.initSign(key);
        signature.update(challenge);
        byte[] signed = signature.sign();
        signature.initVerify(certificateKey);
        signature.update(challenge);
        if (!signature.verify(signed)) {
            throw new GeneralSecurityException("Issuer private key does not match its certificate");
        }
    }

    private static void validatePath(List<X509Certificate> chain, Date when) throws GeneralSecurityException {
        X509Certificate anchor = chain.getLast();
        if (anchor.getSubjectX500Principal().equals(anchor.getIssuerX500Principal())) {
            anchor.verify(anchor.getPublicKey());
        }
        if (chain.size() > 1) {
            var factory = CertificateFactory.getInstance("X.509");
            var path = factory.generateCertPath(chain.subList(0, chain.size() - 1));
            var parameters = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
            parameters.setDate(when);
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
        }
    }
}
