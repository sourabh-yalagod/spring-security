package Spring.Auth.util;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JwtUtil {
    public String generateJwtToken(String payload, long expiryTime) {
        return Jwts.builder()
                .setSubject(payload)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * expiryTime))
                .setIssuedAt(new Date())
                .compact();
    }
}
