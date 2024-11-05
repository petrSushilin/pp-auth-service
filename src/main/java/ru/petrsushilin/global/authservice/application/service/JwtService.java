package ru.petrsushilin.global.authservice.application.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.domain.enitity.enums.Role;
import ru.petrsushilin.global.authservice.domain.enitity.enums.TokenType;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
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

    public Mono<String> generate(String login) {
        return generateTokenPair(login)
                .flatMap(generatedToken ->
                        redisService.registerAccessToken(login, generatedToken.get(TokenType.ACCESS))
                                .switchIfEmpty(Mono.error(new RuntimeException("Failed to register access token")))
                                .filter(Boolean::booleanValue)
                                .then(redisService.registerRefreshToken(login, generatedToken.get(TokenType.REFRESH)))
                                .switchIfEmpty(Mono.error(new RuntimeException("Failed to register refresh token")))
                                .filter(Boolean::booleanValue)
                                .thenReturn(generatedToken.get(TokenType.ACCESS))
                );
    }

    /**
     * Method returns map of token and roles.
     * If access token has expired, but refresh did not, returns refreshed access token and roles.
     * If refresh token has expired or validation failed returns empty Mono.
     * Set of roles can be empty. You should use method Set.contains(Object o).
     *
     * @param token is JWT token of response
     * @return Mono of map consists of current JWT and roles or empty then unsuccessful
     */
    public Mono<Map<String, Set<Role>>> validate(String token) {
        return parseToken(token)
                .switchIfEmpty(Mono.error(new RuntimeException("Token parsing unsuccessful")))
                .flatMap(claims -> isNotExpire(claims)
                        .switchIfEmpty(Mono.error(new RuntimeException("Token has been expired")))
                        .filter(Boolean::booleanValue)
                        .thenReturn(claims.getSubject())
                )
                .flatMap(this::getTokenByRefresh)
                .switchIfEmpty(Mono.empty());
}

    private Mono<Map<String, Set<Role>>> getTokenByRefresh(String login) {
        return redisService.isRefreshTokenHasNotExpire(login)
                .flatMap(isRefreshValid -> isRefreshValid
                        ? generateAccessToken(login)
                        : Mono.empty()
                );
    }

    private Mono<Map<String, Set<Role>>> generateAccessToken(String login) {
        return generateToken(login, jwtAccessExpiration)
                .flatMap(freshToken -> redisService.registerAccessToken(login, freshToken)
                        .filter(Boolean::booleanValue)
                        .flatMap(success -> success
                                ? redisService.getRoles(login).map(roles -> Map.of(freshToken, roles))
                                : Mono.empty()
                        )
                );
    }

    private Mono<Map<TokenType, String>> generateTokenPair(String login) {
        return Mono.zip(
                generateToken(login, jwtAccessExpiration),
                generateToken(login, jwtRefreshExpiration),
                (accessToken, refreshToken) -> Map.of(
                        TokenType.ACCESS, accessToken,
                        TokenType.REFRESH, refreshToken
                )
        );
    }

    private Mono<String> generateToken(String login, long expirationTime) {
        Date issuedAt = new Date();
        return Mono.just(Jwts.builder()
                .subject(login)
                .issuedAt(issuedAt)
                .expiration(Date.from(issuedAt.toInstant().plusMillis(expirationTime)))
                .signWith(privateKey)
                .compact());
    }

    private Mono<Claims> parseToken(String token) {
        return Mono.just(Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload());
    }

    private Mono<Boolean> isNotExpire(Claims claimsJws) {
        return Mono.just(Instant.now().isBefore(claimsJws.getExpiration().toInstant()));
    }
}
