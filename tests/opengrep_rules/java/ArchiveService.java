// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package com.example;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.Random;
import org.apache.commons.lang3.RandomStringUtils;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class ArchiveService {

    private final Random random = new Random();
    private final SecureRandom secureRandom = new SecureRandom();

    String tokens() {
        // ruleid: secreview.java.insecure-random-for-secret
        String resetToken = Long.toHexString(random.nextLong());
        // ruleid: secreview.java.insecure-random-for-secret
        String apiKey = RandomStringUtils.randomAlphanumeric(32);
        // ok: secreview.java.insecure-random-for-secret
        String sessionId = Long.toHexString(secureRandom.nextLong());
        // ok: secreview.java.insecure-random-for-secret
        String password = RandomStringUtils.secure().nextAlphanumeric(32);
        // ok: secreview.java.insecure-random-for-secret
        int jitter = random.nextInt(100);
        return resetToken + apiKey + sessionId + password + jitter;
    }

    void unzip(InputStream input, File destination) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                // ruleid: secreview.java.zip-slip
                File target = new File(destination, entry.getName());
                Files.copy(zip, target.toPath());
            }
        }
    }

    void unzipChecked(InputStream input, Path destination) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                // ok: secreview.java.zip-slip
                Path target = destination.resolve(entry.getName()).normalize();
                if (!target.startsWith(destination)) {
                    throw new IOException("Entry outside the target directory");
                }
                Files.copy(zip, target);
            }
        }
    }

    Object config(String document) {
        // ruleid: secreview.java.snakeyaml-unsafe-load
        Object unsafe = new Yaml().load(document);
        Yaml yaml = new Yaml();
        // ruleid: secreview.java.snakeyaml-unsafe-load
        yaml.load(document);
        Yaml safe = new Yaml(new SafeConstructor(new LoaderOptions()));
        // ok: secreview.java.snakeyaml-unsafe-load
        return safe.load(document);
    }
}
