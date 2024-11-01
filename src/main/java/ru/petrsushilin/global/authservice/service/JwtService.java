package ru.petrsushilin.global.authservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
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
import java.util.stream.Stream;

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
                                .flatMap(successRegisterAccessToken -> {
                                    if (Boolean.TRUE.equals(successRegisterAccessToken)) {
                                        redisService.registerRefreshToken(login, generatedToken.get(TokenType.REFRESH))
                                                .flatMap(successRegisterRefreshToken ->
                                                    Boolean.TRUE.equals(successRegisterRefreshToken)
                                                            ? Mono.just(generatedToken.get(TokenType.ACCESS))
                                                            : Mono.empty()
                                                );
                                    }
                                    return Mono.empty();
                                })
                );
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
    public Mono<Map<String, Set<TokenType>>> validate(String token) {
        Claims claimsJws = this.parseToken(token);
        String login = claimsJws.getSubject();

        if (isNotExpire(claimsJws)) {
            return Mono.just(Map.of(token, redisService.getRoles(login)));
        }

        if (redisService.isRefreshTokenHasNotExpire(login)) {
            String freshToken = generateToken(login, jwtAccessExpiration);

            if (redisService.registerAccessToken(login, freshToken)) {
                return Mono.just(Map.of(freshToken,redisService.getRoles(login)));
            }
        }

        return Mono.empty();
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
