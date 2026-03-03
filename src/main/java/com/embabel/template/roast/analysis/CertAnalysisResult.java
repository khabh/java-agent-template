package com.embabel.template.roast.analysis;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CertAnalysisResult {

    // === 선언 정보 ===
    private final String declaredType;

    // === 기본 메타 ===
    private final int version;
    private final String serialHex;
    private final int serialBitLength;

    // === DN ===
    private final String issuerDn;
    private final String subjectDn;
    private final int subjectRdnCount;
    private final int issuerRdnCount;

    // === Validity ===
    private final Instant notBefore;
    private final Instant notAfter;
    private final long validityDays;

    // === Signature ===
    private final String signatureAlgorithm;
    private final String signatureOid;

    // === Public Key ===
    private final String publicKeyAlgorithm;
    private final int keySize;

    // === Basic Constraints ===
    private final boolean isCa;
    private final Integer pathLenConstraint;
    private final boolean basicConstraintsCritical;

    // === Key Usage ===
    private final Set<String> keyUsages;
    private final Set<String> extendedKeyUsages;

    // === Key Identifiers ===
    private final String subjectKeyIdentifierHex;
    private final String authorityKeyIdentifierHex;
    private final boolean isSelfSigned;

    // === SAN ===
    private final List<String> subjectAltNames;

    // === Extensions ===
    private final Set<String> criticalExtensions;
    private final Set<String> nonCriticalExtensions;
    private final Map<String, Integer> extensionValueSizes;

    // === Raw ===
    private final int derLength;

    public CertAnalysisResult(
        String declaredType,
        int version,
        String serialHex,
        int serialBitLength,
        String issuerDn,
        String subjectDn,
        int subjectRdnCount,
        int issuerRdnCount,
        Instant notBefore,
        Instant notAfter,
        long validityDays,
        String signatureAlgorithm,
        String signatureOid,
        String publicKeyAlgorithm,
        int keySize,
        boolean isCa,
        Integer pathLenConstraint,
        boolean basicConstraintsCritical,
        Set<String> keyUsages,
        Set<String> extendedKeyUsages,
        String subjectKeyIdentifierHex,
        String authorityKeyIdentifierHex,
        boolean isSelfSigned,
        List<String> subjectAltNames,
        Set<String> criticalExtensions,
        Set<String> nonCriticalExtensions,
        Map<String, Integer> extensionValueSizes,
        int derLength
    ) {
        this.declaredType = declaredType;
        this.version = version;
        this.serialHex = serialHex;
        this.serialBitLength = serialBitLength;
        this.issuerDn = issuerDn;
        this.subjectDn = subjectDn;
        this.subjectRdnCount = subjectRdnCount;
        this.issuerRdnCount = issuerRdnCount;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.validityDays = validityDays;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureOid = signatureOid;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.keySize = keySize;
        this.isCa = isCa;
        this.pathLenConstraint = pathLenConstraint;
        this.basicConstraintsCritical = basicConstraintsCritical;
        this.keyUsages = keyUsages;
        this.extendedKeyUsages = extendedKeyUsages;
        this.subjectKeyIdentifierHex = subjectKeyIdentifierHex;
        this.authorityKeyIdentifierHex = authorityKeyIdentifierHex;
        this.isSelfSigned = isSelfSigned;
        this.subjectAltNames = subjectAltNames;
        this.criticalExtensions = criticalExtensions;
        this.nonCriticalExtensions = nonCriticalExtensions;
        this.extensionValueSizes = extensionValueSizes;
        this.derLength = derLength;
    }

    public String summary() {
        return """
               ===== CERT ANALYSIS =====
               declaredType: %s
               version: %d
               serialHex: %s
               serialBitLength: %d
               issuerDn: %s
               subjectDn: %s
               subjectRdnCount: %d
               issuerRdnCount: %d
               notBefore: %s
               notAfter: %s
               validityDays: %d
               signatureAlgorithm: %s (%s)
               publicKeyAlgorithm: %s
               keySize: %d
               isCA: %s
               pathLenConstraint: %s
               basicConstraintsCritical: %s
               keyUsages: %s
               extendedKeyUsages: %s
               SKI: %s
               AKI: %s
               selfSigned: %s
               SANs: %s
               criticalExtensions: %s
               nonCriticalExtensions: %s
               extensionValueSizes: %s
               derLength: %d bytes
               """.formatted(
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
            signatureAlgorithm,
            signatureOid,
            publicKeyAlgorithm,
            keySize,
            isCa,
            pathLenConstraint,
            basicConstraintsCritical,
            keyUsages,
            extendedKeyUsages,
            subjectKeyIdentifierHex,
            authorityKeyIdentifierHex,
            isSelfSigned,
            subjectAltNames,
            criticalExtensions,
            nonCriticalExtensions,
            extensionValueSizes,
            derLength
        );
    }
}