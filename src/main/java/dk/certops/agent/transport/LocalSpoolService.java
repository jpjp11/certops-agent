package dk.certops.agent.transport;

import dk.certops.agent.config.AgentProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

/**
 * Disk-based spool for scan results when cloud is unreachable.
 * Files are stored as JSON in the spool directory and retried later.
 */
@Service
public class LocalSpoolService {

    private static final Logger log = LoggerFactory.getLogger(LocalSpoolService.class);

    private final AgentProperties agentProperties;
    private final ObjectMapper objectMapper;

    public LocalSpoolService(AgentProperties agentProperties, ObjectMapper objectMapper) {
        this.agentProperties = agentProperties;
        this.objectMapper = objectMapper;

        // Ensure spool directory exists
        if (agentProperties.getSpool().isEnabled()) {
            File dir = new File(agentProperties.getSpool().getDirectory());
            if (!dir.exists()) {
                dir.mkdirs();
                log.info("Created spool directory: {}", dir.getAbsolutePath());
            }
        }
    }

    /**
     * Spool a scan batch to disk.
     */
    public void spool(Map<String, Object> scanBatch) {
        if (!agentProperties.getSpool().isEnabled()) {
            log.warn("Spool disabled — dropping scan batch");
            return;
        }

        // Check size limit
        long currentSizeMb = getSpoolSizeMb();
        if (currentSizeMb >= agentProperties.getSpool().getMaxSizeMb()) {
            log.warn("Spool full ({} MB) — dropping scan batch", currentSizeMb);
            return;
        }

        String filename = System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 8) + ".json";
        Path file = Path.of(agentProperties.getSpool().getDirectory(), filename);

        try {
            objectMapper.writeValue(file.toFile(), scanBatch);
            restrictPermissions(file);
            log.info("Spooled scan batch: {}", filename);
        } catch (IOException e) {
            log.error("Failed to spool scan batch: {}", e.getMessage());
        }
    }

    /** Restrict a spooled file to owner-only (600) — it may contain internal scan data. */
    private void restrictPermissions(Path file) {
        try {
            Files.setPosixFilePermissions(file, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem (e.g. Windows) — fall back to directory ACLs.
            log.debug("Could not set spool file permissions to 600: {}", e.getMessage());
        }
    }

    /**
     * Get all spooled files (oldest first).
     */
    public List<Path> getSpooledFiles() {
        File dir = new File(agentProperties.getSpool().getDirectory());
        if (!dir.exists() || !dir.isDirectory()) return List.of();

        try (Stream<Path> stream = Files.list(dir.toPath())) {
            return stream
                    .filter(p -> p.toString().endsWith(".json"))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            log.error("Failed to list spool directory: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Read a spooled file.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> read(Path file) throws IOException {
        return objectMapper.readValue(file.toFile(), Map.class);
    }

    /**
     * Remove a spooled file after successful delivery.
     */
    public void remove(Path file) {
        try {
            Files.deleteIfExists(file);
            log.debug("Removed spooled file: {}", file.getFileName());
        } catch (IOException e) {
            log.warn("Failed to remove spooled file: {}", e.getMessage());
        }
    }

    /**
     * Get count of spooled files.
     */
    public int getQueueSize() {
        return getSpooledFiles().size();
    }

    private long getSpoolSizeMb() {
        File dir = new File(agentProperties.getSpool().getDirectory());
        if (!dir.exists()) return 0;
        long totalBytes = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                totalBytes += f.length();
            }
        }
        return totalBytes / (1024 * 1024);
    }
}
