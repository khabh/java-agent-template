package com.embabel.template.roast.service;

import java.util.Random;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoastImageService {

    private final PathMatchingResourcePatternResolver resolver =
        new PathMatchingResourcePatternResolver();

    private final Random random = new Random();

    public String pickImage(String mode, double score) throws Exception {

        int level = resolveLevel(score);

        String pattern = String.format(
            "classpath:/static/images/%s/level%d/*.*",
            mode,
            level
        );

        Resource[] resources = resolver.getResources(pattern);

        if (resources.length == 0) {
            return null;
        }

        Resource chosen = resources[random.nextInt(resources.length)];

        return String.format(
            "/images/%s/level%d/%s",
            mode,
            level,
            chosen.getFilename()
        );
    }

    private int resolveLevel(double score) {
        if (score <= 3.0) {
            return 1;
        }
        if (score <= 6.0) {
            return 2;
        }
        return 3;
    }
}