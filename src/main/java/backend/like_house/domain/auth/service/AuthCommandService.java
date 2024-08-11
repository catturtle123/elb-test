package backend.like_house.domain.auth.service;

import backend.like_house.domain.auth.dto.AuthDTO;
import backend.like_house.domain.user.entity.User;
import backend.like_house.domain.auth.dto.EmailDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthCommandService {

    AuthDTO.SignUpResponse signUp(AuthDTO.SignUpRequest request);

    void signIn(HttpServletResponse response, AuthDTO.SignInRequest request);

    void signOut(HttpServletRequest request, HttpServletResponse response);

    void deleteUser(HttpServletRequest request, HttpServletResponse response);

    EmailDTO.EmailSendResponse sendCode(String email);

    void verifyCode(EmailDTO.EmailVerificationRequest request);

    void fcmSave(User user, AuthDTO.FcmRequest tokenRequest);

    void fcmSignOut(User user);
}
