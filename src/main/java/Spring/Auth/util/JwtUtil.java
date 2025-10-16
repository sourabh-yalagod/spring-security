package Spring.Auth.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
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
}
