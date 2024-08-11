package backend.like_house.domain.auth.service;

import backend.like_house.domain.auth.dto.AuthDTO;
import backend.like_house.domain.user.entity.User;
import backend.like_house.domain.auth.dto.EmailDTO;

public interface AuthCommandService {

    AuthDTO.SignUpResponse signUp(AuthDTO.SignUpRequest request);

    AuthDTO.SignInResponse signIn(AuthDTO.SignInRequest request);

    void signOut(AuthDTO.TokenRequest request);

    void deleteUser(AuthDTO.TokenRequest request);

    EmailDTO.EmailSendResponse sendCode(String email);

    void verifyCode(EmailDTO.EmailVerificationRequest request);

    void fcmSave(User user, AuthDTO.FcmRequest tokenRequest);

    void fcmSignOut(User user);
}
