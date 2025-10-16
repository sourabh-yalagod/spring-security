package Spring.Auth.types;

import Spring.Auth.ProviderType;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class AuthUtil {
    private static final String key = String.valueOf(Keys.secretKeyFor(SignatureAlgorithm.HS256));

    public SecretKey secreteKey() {
        return Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
    }

    public String generateJwtToken(String payload, long expiryTime) {
        return Jwts.builder().setSubject(payload).setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * expiryTime)).setIssuedAt(new Date()).signWith(this.secreteKey()).compact();
    }

    public boolean validateToken(String token) {
        try {
            Object payload = Jwts.parserBuilder().setSigningKey(this.secreteKey()).build().parseClaimsJws(token);
            System.out.println("payload : " + payload);
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public ProviderType getAuthProvider(String providerId) {
        return switch (providerId.toLowerCase()) {
            case "google" -> ProviderType.GOOGLE;
            case "github" -> ProviderType.GITHUB;
            default -> throw new IllegalStateException("Unexpected value: " + providerId.toLowerCase());
        };
    }

    public String getAuthProviderId(OAuth2User oAuth2User, String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id");
            default -> throw new IllegalStateException("Unexpected value: " + registrationId.toLowerCase());
        };
    }

    public String getIdentifierFromOAuth2Object(OAuth2User oAuth2User, String registrationId) {
        String email = oAuth2User.getAttribute("email");
        if (email != null && !email.isEmpty()) return email;
        return switch (registrationId.toLowerCase()) {
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id");
            default -> registrationId.toLowerCase();
        };
    }
}
