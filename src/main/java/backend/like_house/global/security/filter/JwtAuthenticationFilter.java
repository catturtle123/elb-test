package backend.like_house.global.security.filter;

import backend.like_house.domain.user.entity.SocialType;
import backend.like_house.global.error.code.status.ErrorStatus;
import backend.like_house.global.error.handler.AuthException;
import backend.like_house.global.security.util.JWTUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String accessToken = resolveToken(request);
        String refreshToken = resolveRefreshToken(request);

        if (accessToken == null && refreshToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        if (accessToken == null) {
            handleNoAccessToken(response, refreshToken);
        } else {
            handleAccessToken(request, response, accessToken, refreshToken);
        }

        filterChain.doFilter(request, response);
    }

    private void handleNoAccessToken(HttpServletResponse response, String refreshToken) throws IOException {
        if (refreshToken != null) {
            try {
                String newAccessToken = jwtUtil.renewAccessToken(refreshToken);
                setCookie(response, "accessToken", newAccessToken, 600);

                String email = jwtUtil.extractEmail(newAccessToken);
                SocialType socialType = jwtUtil.extractSocialName(newAccessToken);

                validateAndSetAuthentication(newAccessToken, email, socialType);

            } catch (JwtException | IllegalArgumentException e) {
                throw new AuthException(ErrorStatus.INVALID_TOKEN);
            }
        } else {
            throw new AuthException(ErrorStatus._UNAUTHORIZED);
        }
    }

    private void handleAccessToken(HttpServletRequest request, HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        try {
            // 블랙리스트 확인
            String blacklist = redisTemplate.opsForValue().get(accessToken);
            if (blacklist != null) {
                if ("logoutUser".equals(blacklist)) {
                    throw new AuthException(ErrorStatus.LOGOUT_USER_TOKEN);
                } else {
                    throw new AuthException(ErrorStatus.DELETE_USER_TOKEN);
                }
            }

            // 액세스 토큰이 만료되었는지 확인
            if (jwtUtil.isTokenExpired(accessToken)) {
                if (refreshToken != null) {
                    handleNoAccessToken(response, refreshToken);
                } else {
                    throw new AuthException(ErrorStatus.EXPIRED_TOKEN);
                }
            } else {
                // 액세스 토큰이 유효한 경우 인증 객체 설정
                String email = jwtUtil.extractEmail(accessToken);
                SocialType socialType = jwtUtil.extractSocialName(accessToken);
                if (email != null && socialType != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    Authentication authentication = jwtUtil.getAuthentication(email, socialType);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

        } catch (JwtException | IllegalArgumentException e) {
            throw new AuthException(ErrorStatus.INVALID_TOKEN);
        }
    }

    private String resolveToken(HttpServletRequest request) {
        // 헤더에서 액세스 토큰을 꺼냄
        String bearer = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }

        // 쿠키에서 액세스 토큰을 꺼냄
        return getCookieValue(request, "accessToken");
    }

    private String resolveRefreshToken(HttpServletRequest request) {
        // 쿠키에서 리프레시 토큰을 꺼냄
        return getCookieValue(request, "refreshToken");
    }

    private String getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    private void validateAndSetAuthentication(String token, String email, SocialType socialType) {
        String blacklist = redisTemplate.opsForValue().get(token);
        if (blacklist != null) {
            throw new AuthException("logoutUser".equals(blacklist) ? ErrorStatus.LOGOUT_USER_TOKEN : ErrorStatus.DELETE_USER_TOKEN);
        }
        Authentication authentication = jwtUtil.getAuthentication(email, socialType);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
