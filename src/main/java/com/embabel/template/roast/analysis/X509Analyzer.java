package com.embabel.template.roast.analysis;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.springframework.stereotype.Service;

@Service
public class X509Analyzer {

    public CertAnalysisResult analyze(byte[] certBytes, String declaredType) throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)
            factory.generateCertificate(new ByteArrayInputStream(certBytes));

        // === Version ===
        int version = cert.getVersion();

        // === Serial ===
        BigInteger serial = cert.getSerialNumber();
        String serialHex = serial.toString(16);
        int serialBitLength = serial.bitLength();

        // === DN ===
        X500Principal issuer = cert.getIssuerX500Principal();
        X500Principal subject = cert.getSubjectX500Principal();

        String issuerDn = issuer.getName();
        String subjectDn = subject.getName();

        int issuerRdnCount = issuerDn.split(",").length;
        int subjectRdnCount = subjectDn.split(",").length;

        // === Validity ===
        Instant notBefore = cert.getNotBefore().toInstant();
        Instant notAfter = cert.getNotAfter().toInstant();
        long validityDays = ChronoUnit.DAYS.between(notBefore, notAfter);

        // === Signature ===
        String sigAlgName = cert.getSigAlgName();
        String sigAlgOid = cert.getSigAlgOID();

        // === Public Key ===
        PublicKey publicKey = cert.getPublicKey();
        String publicKeyAlgorithm = publicKey.getAlgorithm();
        int keySize = 0;

        if (publicKey instanceof RSAPublicKey rsa) {
            keySize = rsa.getModulus().bitLength();
        }

        // === Basic Constraints ===
        int basicConstraints = cert.getBasicConstraints();

        boolean isCa = basicConstraints >= 0;

        Integer pathLen = null;

        if (isCa) {
            // Some implementations return Integer.MAX_VALUE when pathLen is not explicitly set
            if (basicConstraints != Integer.MAX_VALUE) {
                pathLen = basicConstraints;
            }
        }

        boolean basicConstraintsCritical =
            cert.getCriticalExtensionOIDs() != null &&
                cert.getCriticalExtensionOIDs().contains("2.5.29.19");

        // === Key Usage ===
        Set<String> keyUsages = new HashSet<>();
        boolean[] ku = cert.getKeyUsage();
        if (ku != null) {
            String[] names = {
                "digitalSignature", "nonRepudiation", "keyEncipherment",
                "dataEncipherment", "keyAgreement", "keyCertSign",
                "cRLSign", "encipherOnly", "decipherOnly"
            };
            for (int i = 0; i < ku.length && i < names.length; i++) {
                if (ku[i]) {
                    keyUsages.add(names[i]);
                }
            }
        }

        Set<String> extendedKeyUsages = new HashSet<>();
        if (cert.getExtendedKeyUsage() != null) {
            extendedKeyUsages.addAll(cert.getExtendedKeyUsage());
        }

        // === Self Signed ===
        boolean isSelfSigned = issuerDn.equals(subjectDn);

        // === SAN ===
        List<String> sans = new ArrayList<>();
        Collection<List<?>> sanCollection = cert.getSubjectAlternativeNames();
        if (sanCollection != null) {
            for (List<?> item : sanCollection) {
                sans.add(String.valueOf(item.get(1)));
            }
        }

        // === Extensions ===
        Set<String> criticalExt = Optional.ofNullable(cert.getCriticalExtensionOIDs())
                                          .orElse(Collections.emptySet());

        Set<String> nonCriticalExt = Optional.ofNullable(cert.getNonCriticalExtensionOIDs())
                                             .orElse(Collections.emptySet());

        Map<String, Integer> extSizes = new HashMap<>();
        Set<String> allOids = new HashSet<>();
        allOids.addAll(criticalExt);
        allOids.addAll(nonCriticalExt);

        for (String oid : allOids) {
            byte[] value = cert.getExtensionValue(oid);
            if (value != null) {
                extSizes.put(oid, value.length);
            }
        }

        int derLength = cert.getEncoded().length;

        return new CertAnalysisResult(
            declaredType,
            version,
            serialHex,
            serialBitLength,
            issuerDn,
            subjectDn,
            subjectRdnCount,
            issuerRdnCount,
            notBefore,
            notAfter,
            validityDays,
            sigAlgName,
            sigAlgOid,
            publicKeyAlgorithm,
            keySize,
            isCa,
            pathLen,
            basicConstraintsCritical,
            keyUsages,
            extendedKeyUsages,
            null,
            null,
            isSelfSigned,
            sans,
            criticalExt,
            nonCriticalExt,
            extSizes,
            derLength
        );
    }
}