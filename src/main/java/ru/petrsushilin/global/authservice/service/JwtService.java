package ru.petrsushilin.global.authservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.petrsushilin.global.authservice.enitity.enums.TokenType;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
public class JwtService {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Value("${jwt.access.expiration}")
    private long jwtAccessExpiration;
    @Value("${jwt.refresh.expiration}")
    private long jwtRefreshExpiration;

    private final RedisService redisService;

    public JwtService(
            @Value("${JWT_PRIVATE_KEY}") String privateKeyEncoded,
            @Value("${JWT_PUBLIC_KEY}") String publicKeyEncoded,
            RedisService redisService
    ) throws Exception {
        this.privateKey = loadPrivateKey(privateKeyEncoded);
        this.publicKey = loadPublicKey(publicKeyEncoded);
        this.redisService = redisService;
    }

    private PrivateKey loadPrivateKey(String privateKeyEncoded) throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyEncoded)));
    }

    private PublicKey loadPublicKey(String publicKeyEncoded) throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyEncoded)));
    }

    public Optional<String> generate(String login) {
        Map<TokenType, String> generatedTokens = generateTokenPair(login);

        if (redisService.registerAccessToken(login, generatedTokens.get(TokenType.ACCESS)) &
                redisService.registerRefreshToken(login, generatedTokens.get(TokenType.REFRESH))) {
            return Optional.of(generatedTokens.get(TokenType.ACCESS));
        }

        return Optional.empty();
    }

    /**
     * Method returns map of token and roles.
     * If access token has expired returns refresh token and roles.
     * If refresh token has expired or validation failed returns empty Optional.
     * Set of roles can be empty. You should use method Set.contains(Object o).
     *
     * @param token is JWT token of response
     * @return Optional of map consists of current JWT and roles
     */
    public Optional<Map<String, Set<String>>> validate(String token) {
        Claims claimsJws = this.parseToken(token);
        String login = claimsJws.getSubject();

        if (isNotExpire(claimsJws)) {
            return Optional.of(Map.of(token, redisService.getRoles(login)));
        }

        if (redisService.isRefreshTokenHasNotExpire(login)) {
            String freshToken = generateToken(login, jwtAccessExpiration);

            if (redisService.registerAccessToken(login, freshToken)) {
                return Optional.of(Map.of(freshToken,redisService.getRoles(login)));
            }
        }

        return Optional.empty();
    }

    private Map<TokenType, String> generateTokenPair(String login) {
        return Map.of(
                TokenType.ACCESS, generateToken(login, jwtAccessExpiration),
                TokenType.REFRESH, generateToken(login, jwtRefreshExpiration)
        );
    }

    private String generateToken(String login, long expirationTime) {
        Date issuedAt = new Date();
        return Jwts.builder()
                .subject(login)
                .issuedAt(issuedAt)
                .expiration(Date.from(issuedAt.toInstant().plusMillis(expirationTime)))
                .signWith(privateKey)
                .compact();
    }

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isNotExpire(Claims claimsJws) {
        return Instant.now().isBefore(claimsJws.getExpiration().toInstant());
    }
}
