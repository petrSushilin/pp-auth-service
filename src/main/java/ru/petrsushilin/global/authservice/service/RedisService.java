package ru.petrsushilin.global.authservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.enitity.enums.Role;
import ru.petrsushilin.global.authservice.enitity.enums.TokenType;
import ru.petrsushilin.global.authservice.repository.AccountRepository;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class RedisService {
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;
    private final AccountRepository repository;

    @Value("${jwt.access.expiration}")
    private long jwtAccessExpiration;
    @Value("${jwt.refresh.expiration}")
    private long jwtRefreshExpiration;

    public RedisService(ReactiveRedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper, AccountRepository repository) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.repository = repository;
    }

    public Flux<String> refreshRoles(String login) {
        return repository.getRolesByLogin(login)
                .flatMapMany(roles -> {
                    return redisTemplate.opsForHash()
                            .put(TokenType.ACCESS.name() + ":" + login,"roles", roles)
                            .thenMany(Flux.fromIterable(roles));
                });
    }

    Mono<Boolean> registerAccessToken(String login, String jwtAccessToken) {
        String accessKey = TokenType.ACCESS.name() + ":" + login;

        return repository.getRolesByLogin(login)
                .flatMap(roles -> {
                    Map<String, String> accessData = new HashMap<>();
                    accessData.put("token", jwtAccessToken);

                    try {
                        accessData.put("roles", objectMapper.writeValueAsString(roles));
                    } catch (JsonProcessingException e) {
                        return Mono.error(new RuntimeException("Failed to serialize roles", e));
                    }

                    return redisTemplate.opsForHash().putAll(accessKey, accessData)
                            .flatMap(success -> {
                                if (Boolean.TRUE.equals(success)) {
                                    return redisTemplate.expire(accessKey, Duration.ofMillis(jwtAccessExpiration));
                                }
                                return Mono.just(false);
                            });
                })
                .onErrorReturn(false);
    }

    Mono<Boolean> registerRefreshToken(String login, String jwtRefreshToken) {
        return redisTemplate.opsForValue()
                .set(TokenType.REFRESH.name() + ":" + login, jwtRefreshToken, Duration.ofMillis(jwtRefreshExpiration))
                .map(result -> result != null && result);
    }

    Flux<Role> getRoles(String login) {
        return redisTemplate.opsForHash().get(TokenType.ACCESS.name() + ":" + login, "roles")
                .flatMapMany(role -> {
                    try {
                        return Flux.fromIterable(objectMapper.readValue((String) role, new TypeReference<Set<Role>>() {}));
                    } catch (JsonProcessingException e) {
                        return Flux.error(new RuntimeException("Failed to deserialize roles", e));
                    }
                });
    }

    Mono<Boolean> isRefreshTokenHasNotExpire(String login) {
        return redisTemplate.getExpire(TokenType.REFRESH.name() + ":" + login)
                .flatMap(duration -> {
                    return duration != null && !duration.isNegative() ? Mono.just(true) : Mono.just(false);
                })
                .defaultIfEmpty(false);
    }
}
