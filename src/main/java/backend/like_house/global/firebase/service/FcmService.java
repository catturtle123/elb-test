package backend.like_house.global.firebase.service;

import backend.like_house.domain.auth.dto.AuthDTO;
import backend.like_house.domain.auth.repository.AuthRepository;
import backend.like_house.domain.auth.service.AuthCommandService;
import backend.like_house.domain.notification.service.NotificationCommandService;
import backend.like_house.domain.user.entity.User;
import backend.like_house.global.error.code.status.ErrorStatus;
import backend.like_house.global.error.exception.alarmClient.dto.DiscordMessage;
import backend.like_house.global.error.exception.alarmClient.service.DiscordClient;
import backend.like_house.global.error.handler.AuthException;
import backend.like_house.global.error.handler.TokenException;
import backend.like_house.global.security.util.JWTUtil;
import com.google.firebase.FirebaseException;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class FcmService {

    private final DiscordClient discordClient;
    private final AuthCommandService authCommandService;


    public void sendNotification(User receiver, String title, String body) {

        if (!(receiver.getFcmToken() == null)) {
            Notification notification = Notification.builder()
                    .setTitle(title)
                    .setBody(body)
                    .build();

            Message message = Message.builder()
                    .setToken(receiver.getFcmToken())
                    .setNotification(notification)
                    .build();

            try {
                FirebaseMessaging.getInstance().send(message);
            } catch (FirebaseMessagingException e) {
                e.printStackTrace();
                authCommandService.fcmSignOut(receiver);
                discordClient.sendAlarm(createMessage(receiver, title, body));
            }
        }
    }

    private DiscordMessage createMessage(User receiver, String title, String content) {
        return DiscordMessage.builder()
                .content("# 🚨 에러 발생 비이이이이사아아아앙")
                .embeds(
                        List.of(
                                DiscordMessage.Embed.builder()
                                        .title("ℹ️ 에러 정보")
                                        .description(String.format("%s(%d)가 유효하지 않은 fcm token값을 가지고 있습니다.", receiver.getName(), receiver.getId()))
                                        .build()))
                .build();
    }
}
