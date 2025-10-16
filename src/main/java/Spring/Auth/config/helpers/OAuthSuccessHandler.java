package Spring.Auth.config.helpers;

import Spring.Auth.dtos.LoginResponseDto;
import Spring.Auth.service.UserService;
import Spring.Auth.types.AuthUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {
    private final UserService userService;
    private final ObjectMapper objectMapper;

    public OAuthSuccessHandler(UserService userService, ObjectMapper objectMapper) {
        this.userService = userService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();
        String registrationId = token.getAuthorizedClientRegistrationId();
        try {
            LoginResponseDto loginResponseDto = userService.handleOAuth2User(oAuth2User, registrationId);
            System.out.println("36 : " + loginResponseDto);
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.setContentType("application/json");
            String jsonResponse = objectMapper.writeValueAsString(loginResponseDto);
            response.getWriter().write(jsonResponse);
            response.getWriter().flush();
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"" + e.getMessage() + "\"}");
            response.getWriter().flush();
        }

    }
}
