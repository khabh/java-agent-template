package com.embabel.template.roast.service;

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
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CertRoastService {

    private final X509Analyzer analyzer;
    private final AgentPlatform agentPlatform;

    public CertRoastAgent.RoastResult roast(
        byte[] certBytes,
        String type
    ) throws Exception {

        CertAnalysisResult analysis =
            analyzer.analyze(certBytes, type);

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

        return process.resultOfType(
            CertRoastAgent.RoastResult.class
        );
    }
}