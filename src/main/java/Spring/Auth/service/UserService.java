package Spring.Auth.service;

import Spring.Auth.ProviderType;
import Spring.Auth.dtos.LoginResponseDto;
import Spring.Auth.entity.UserEntity;
import Spring.Auth.repository.UserRepository;
import Spring.Auth.types.AuthUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final AuthUtil authUtil;

    public UserService(UserRepository userRepository, AuthUtil authUtil) {
        this.userRepository = userRepository;
        this.authUtil = authUtil;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username);
    }

    @Transactional
    public LoginResponseDto handleOAuth2User(OAuth2User oAuth2User, String registrationId) throws Exception {
        ProviderType authProvider = authUtil.getAuthProvider(registrationId);
        String authProviderId = authUtil.getAuthProviderId(oAuth2User, registrationId);
        System.out.println("authProvider : " + authProvider + "authProviderId : " + authProviderId);
        UserEntity user = userRepository.findByProviderAndProviderId(authProvider, authProviderId);
        String email = oAuth2User.getAttribute("email");
        UserEntity userByEmail = userRepository.findByUsername(email);
        if (userByEmail == null && user == null) {
            String identifier = authUtil.getIdentifierFromOAuth2Object(oAuth2User, registrationId);
            user = UserEntity.builder()
                    .provider(authProvider)
                    .providerId(authProviderId)
                    .username(identifier)
                    .password(null)
                    .build();
            userRepository.save(user);
        } else if (user != null) {
            if (email != null && !email.isBlank() && email.equals(user.getUsername())) {
                user.setUsername(email);
                userRepository.save(user);
            }
        } else {
            throw new Exception("Username Already exist please try with password....!");
        }
        String accessToken = authUtil.generateJwtToken(user.getUsername(), 5);
        String refreshToken = authUtil.generateJwtToken(user.getUsername(), 60 * 24 * 7);
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        LoginResponseDto loginResponseDto = new LoginResponseDto(user.getId(), accessToken, user.getRefreshToken());
        System.out.println("LoginResponseDto : " + loginResponseDto);
        return loginResponseDto;
    }
}