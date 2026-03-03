package com.embabel.template.roast.presentation;


import com.embabel.agent.core.Agent;
import com.embabel.agent.core.AgentPlatform;
import com.embabel.agent.core.AgentProcess;
import com.embabel.agent.core.ProcessOptions;
import com.embabel.agent.domain.io.UserInput;
import com.embabel.template.roast.agent.CertRoastAgent;
import com.embabel.template.roast.analysis.CertAnalysisResult;
import com.embabel.template.roast.analysis.X509Analyzer;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequiredArgsConstructor
@RequestMapping("/roast")
public class CertRoastController {

    private final X509Analyzer analyzer;
    private final AgentPlatform agentPlatform;

    @GetMapping
    public String form() {
        return "roast-form";
    }

    @PostMapping
    public String roast(@RequestParam String type, @RequestParam("file") MultipartFile file, Model model)
        throws Exception {
        CertAnalysisResult analysis = analyzer.analyze(file.getBytes(), type);

        Agent agent = agentPlatform.agents().stream()
                                   .filter(a -> a.getName().equals("CertRoastAgent"))
                                   .findFirst()
                                   .orElseThrow();

        AgentProcess process = agentPlatform.createAgentProcess(
            agent,
            ProcessOptions.DEFAULT,
            Map.of("input", new UserInput(analysis.summary()))
        );

        agentPlatform.start(process).join();

        CertRoastAgent.RoastResult result =
            process.resultOfType(CertRoastAgent.RoastResult.class);

        model.addAttribute("result", result);
        model.addAttribute("type", type);

        return "roast-form";
    }
}