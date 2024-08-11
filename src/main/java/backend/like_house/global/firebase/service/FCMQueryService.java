package backend.like_house.global.firebase.service;

import backend.like_house.global.error.code.status.ErrorStatus;
import backend.like_house.global.error.handler.AuthException;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class FCMQueryService {

    public void isTokenValid(String sender, String token) {
        Notification notification = Notification.builder()
                .setTitle(sender)
                .setBody("토큰 인증 되었 습니다.")
                .build();

        Message message = Message.builder()
                .setToken(token)
                .setNotification(notification)
                .build();

        try {
            FirebaseMessaging.getInstance().send(message);
        } catch (FirebaseMessagingException e) {
            throw new AuthException(ErrorStatus.TOKEN_NOT_VALID);
        }
    }
}
