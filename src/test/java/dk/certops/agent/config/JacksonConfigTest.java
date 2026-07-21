package dk.certops.agent.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the hand-rolled ObjectMapper that replaced Spring Boot's auto-configured one when
 * spring-boot-starter-web was dropped from the agent.
 */
class JacksonConfigTest {

    private final ObjectMapper mapper = new JacksonConfig().objectMapper();

    @Test
    void unknownPropertiesAreIgnored() throws Exception {
        // The cloud may add config fields at any time; deployed agents must not break on them.
        Map<?, ?> result = mapper.readValue("{\"knownField\":1,\"fieldAddedLater\":\"x\"}", Map.class);

        assertEquals(1, result.get("knownField"));
        assertEquals("x", result.get("fieldAddedLater"));
        assertFalse(mapper.isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES));
    }

    @Test
    void javaTimeIsSerializedAsIso8601NotEpochArray() throws Exception {
        String json = mapper.writeValueAsString(Map.of("ts", Instant.parse("2026-07-21T05:00:00Z")));

        assertTrue(json.contains("\"2026-07-21T05:00:00Z\""), "expected ISO-8601 string, got: " + json);
        assertFalse(mapper.isEnabled(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS));
    }

    @Test
    void javaTimeCanBeDeserialized() throws Exception {
        Instant parsed = mapper.readValue("\"2026-07-21T05:00:00Z\"", Instant.class);

        assertEquals(Instant.parse("2026-07-21T05:00:00Z"), parsed);
    }

    @Test
    void defaultViewInclusionIsDisabled() {
        assertFalse(mapper.isEnabled(MapperFeature.DEFAULT_VIEW_INCLUSION));
    }
}
