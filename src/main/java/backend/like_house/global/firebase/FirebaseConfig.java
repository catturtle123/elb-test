package backend.like_house.global.firebase;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Configuration
@Slf4j
public class FirebaseConfig {

    @Value("${spring.firebase.config}")
    private String firebaseConfig;

    @Bean
    public FirebaseApp firebaseApp() throws IOException {
        log.info(firebaseConfig);
        ByteArrayInputStream serviceAccountStream = new ByteArrayInputStream(firebaseConfig.getBytes());

        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(GoogleCredentials.fromStream(serviceAccountStream))
                .build();

        // FirebaseApp 인스턴스를 초기화하고 반환
        return FirebaseApp.initializeApp(options);
    }
}
