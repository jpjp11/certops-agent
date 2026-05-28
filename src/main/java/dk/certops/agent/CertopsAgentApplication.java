package dk.certops.agent;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class CertopsAgentApplication {

    public static void main(String[] args) {
        SpringApplication.run(CertopsAgentApplication.class, args);
    }
}
