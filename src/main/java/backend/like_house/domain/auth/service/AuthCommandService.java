package backend.like_house.domain.auth.service;

import backend.like_house.domain.auth.dto.AuthDTO;
import backend.like_house.domain.auth.dto.EmailDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthCommandService {

    AuthDTO.SignUpResponse signUp(AuthDTO.SignUpRequest request);

    AuthDTO.SignInResponse signIn(AuthDTO.SignInRequest request);

    void signOut(HttpServletRequest request, HttpServletResponse response);

    void deleteUser(HttpServletRequest request, HttpServletResponse response);

    EmailDTO.EmailSendResponse sendCode(String email);

    void verifyCode(EmailDTO.EmailVerificationRequest request);

}
