package dk.certops.agent.exposure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;

public class ScanWindowChecker {

    private static final Logger log = LoggerFactory.getLogger(ScanWindowChecker.class);

    @SuppressWarnings("unchecked")
    public static boolean isWithinWindow(Map<String, Object> scanWindow) {
        if (scanWindow == null || scanWindow.isEmpty()) return true;

        try {
            String startStr = (String) scanWindow.get("start");
            String endStr = (String) scanWindow.get("end");
            String tzStr = (String) scanWindow.getOrDefault("timezone", "UTC");

            if (startStr == null || endStr == null) return true;

            ZoneId zone = ZoneId.of(tzStr);
            LocalTime start = LocalTime.parse(startStr);
            LocalTime end = LocalTime.parse(endStr);
            LocalTime now = ZonedDateTime.now(zone).toLocalTime();

            if (start.isBefore(end)) {
                return !now.isBefore(start) && !now.isAfter(end);
            } else {
                // Window spans midnight (e.g., 22:00 to 06:00)
                return !now.isBefore(start) || !now.isAfter(end);
            }
        } catch (Exception e) {
            log.warn("Failed to parse scan window, allowing scan: {}", e.getMessage());
            return true;
        }
    }
}
