package com.embabel.template.roast.presentation;


import com.embabel.agent.core.AgentPlatform;
import com.embabel.template.roast.agent.CertRoastAgent;
import com.embabel.template.roast.analysis.X509Analyzer;
import com.embabel.template.roast.service.CertRoastService;
import com.embabel.template.roast.service.RoastImageService;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/roast")
public class CertRoastController {

    private final X509Analyzer analyzer;
    private final AgentPlatform agentPlatform;
    private final CertRoastService certRoastService;
    private final RoastImageService roastImageService;

    @GetMapping
    public String form() {
        return "roast-form";
    }

    @PostMapping
    public String roast(
        @RequestParam String type,
        @RequestParam String inputMode,
        @RequestParam String resultMode,
        @RequestParam(value = "file", required = false) MultipartFile file,
        @RequestParam(value = "pemText", required = false) String pemText,
        Model model
    ) throws Exception {

        byte[] certBytes = resolveCertificate(inputMode, file, pemText);
        CertRoastAgent.RoastResult result =
            new CertRoastAgent.RoastResult(
                5f,
                "result"
            );
//          certRoastService.roast(certBytes, type);
        String imagePath = roastImageService.pickImage(resultMode, result.score());
        model.addAttribute("result", result);
        model.addAttribute("type", type);
        model.addAttribute("inputMode", inputMode);
        model.addAttribute("imagePath", imagePath);
        model.addAttribute("resultMode", resultMode);

        return "roast-form";
    }

    private byte[] parsePem(String pem) {
        String normalized = pem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replaceAll("\\s", "");

        return Base64.getDecoder().decode(normalized);
    }

    private byte[] resolveCertificate(
        String inputMode,
        MultipartFile file,
        String pemText
    ) throws Exception {

        if ("pem".equals(inputMode)) {

            if (pemText == null || pemText.isBlank()) {
                throw new IllegalArgumentException("PEM text is empty");
            }

            return parsePem(pemText);
        }

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Certificate file is empty");
        }

        return file.getBytes();
    }
}