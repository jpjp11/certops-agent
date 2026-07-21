package dk.certops.agent.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Supplies the {@link ObjectMapper} the transport and scheduler layers depend on.
 *
 * <p>The agent used to get this bean for free from Spring Boot's Jackson auto-configuration,
 * which arrived transitively via spring-boot-starter-web. That starter was dropped — the agent
 * serves no HTTP endpoints, so it was only contributing an embedded Tomcat on a random port
 * plus CVE surface — which takes the auto-configured mapper with it.
 *
 * <p>The settings below reproduce the ones Boot applied, so serialization behaviour is
 * unchanged. {@code FAIL_ON_UNKNOWN_PROPERTIES} in particular must stay disabled: the agent
 * deserializes config pulled from the cloud, and a stricter mapper would break every deployed
 * agent the moment the server adds a field.
 */
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return JsonMapper.builder()
                .addModule(new JavaTimeModule())
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(MapperFeature.DEFAULT_VIEW_INCLUSION)
                .build();
    }
}
