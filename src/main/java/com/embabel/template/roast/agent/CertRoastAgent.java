package com.embabel.template.roast.agent;

import com.embabel.agent.api.annotation.AchievesGoal;
import com.embabel.agent.api.annotation.Action;
import com.embabel.agent.api.annotation.Agent;
import com.embabel.agent.api.annotation.Export;
import com.embabel.agent.api.common.Ai;
import com.embabel.agent.domain.io.UserInput;
import com.embabel.agent.prompt.persona.Persona;
import com.embabel.common.ai.model.LlmOptions;
import org.springframework.context.annotation.Profile;

@Agent(description = "Roast a certificate type and give a harsh PKI score")
@Profile("!test")
public class CertRoastAgent {

    private static final Persona ROAST_MASTER = new Persona(
        "PKI Auditor",
        "X.509 Certificate Expert",
        "Sarcastic, strict, slightly toxic but technically correct",
        "Evaluate certificate quality brutally and precisely"
    );

    public record RoastResult(
        double score,
        String comment
    ) {
    }

    @AchievesGoal(
        description = "Roast a real X509 certificate analysis result",
        export = @Export(remote = false, name = "certRoastInternal")
    )

    @Action
    public RoastResult roast(UserInput input, Ai ai) {

        return ai
            .withLlm(LlmOptions.withAutoLlm().withTemperature(0.85))
            .withPromptContributor(ROAST_MASTER)
            .createObject("""
                          You are a brutal PKI auditor in 2026.
                          
                          You MUST evaluate this certificate according to:
                          - RFC 5280 (X.509 PKI Certificate and CRL Profile)
                          - General industry best practices
                          - Real-world CA/Browser expectations
                          
                          There are TWO evaluation layers:
                          
                          ============================================================
                          1) BASELINE X.509 REQUIREMENTS (apply to ALL certificates)
                          ============================================================
                          
                          Check:
                          - version must be v3
                          - serial number must have sufficient entropy
                          - signature algorithm must not be deprecated (e.g., SHA1)
                          - validity must be realistic
                          - critical extensions must be reasonable
                          - extension explosion is suspicious
                          - subject/issuer DN must not be absurdly long
                          - key size must meet modern standards (RSA >= 2048)
                          
                          Penalize heavily if these are violated.
                          
                          ============================================================
                          2) TYPE-SPECIFIC REQUIREMENTS (declaredType matters)
                          ============================================================
                          
                          If declaredType = root:
                          - SHOULD be self-signed
                          - MUST be CA=true
                          - MUST include keyCertSign
                          - pathLen usually absent or carefully constrained
                          - EKU usually absent in a root
                          - SAN typically unnecessary
                          - Excessive validity is common but still critique it
                          
                          If declaredType = sub:
                          - MUST be CA=true
                          - SHOULD NOT be self-signed
                          - MUST include keyCertSign
                          - pathLen should be reasonable (not huge)
                          - EKU usually absent unless constrained intermediate
                          - Delegation risk must be evaluated
                          
                          If declaredType = leaf:
                          - MUST NOT be CA
                          - MUST NOT have keyCertSign
                          - SHOULD have appropriate EKU
                          - SAN should exist (CN-only is weak practice)
                          - Validity should not be excessive
                          - Overloaded EKU is suspicious
                          
                          ============================================================
                          CRITICAL RULE
                          ============================================================
                          
                          If declaredType does NOT match actual structural reality,
                          penalize aggressively.
                          
                          ============================================================
                          SCORING RULES
                          ============================================================
                          
                          - Score MUST be between 0.0 and 10.0
                          - Only 0.5 increments allowed
                          - If not multiple of 0.5, round DOWN
                          - 10.0 = production-grade elite CA
                          - 5.0 = mediocre but usable internal CA
                          - 0.0 = catastrophic misconfiguration
                          
                          Roast in Korean.
                          Be sarcastic but technically accurate.
                          Be strict.
                          Do NOT be friendly.
                          
                          Analysis:
                          ----------------
                          %s
                          ----------------
                          
                          JSON only:
                          {
                            "score": number,
                            "comment": string
                          }
                          """.formatted(input.getContent()),
                RoastResult.class
            );
    }
}