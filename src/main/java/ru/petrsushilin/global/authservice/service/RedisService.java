package ru.petrsushilin.global.authservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.enitity.enums.TokenType;
import ru.petrsushilin.global.authservice.repository.AccountRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

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

    public Mono<Set<String>> refreshRoles(String login) {
        return repository.getRolesByLogin(login)
                .flatMap(roles -> {
                    redisTemplate.opsForHash().put(TokenType.ACCESS.name() + ":" + login,"roles", roles);
                    return Mono.just(roles);
                });
    }

    Mono<Boolean> registerAccessToken(String login, String jwtAccessToken) {
        String accessKey = TokenType.ACCESS.name() + ":" + login;

        return repository.getRolesByLogin(login)
                .<Boolean>handle((roles, sink) -> {
                    Map<String, String> accessData = new HashMap<>();
                    accessData.put("token", jwtAccessToken);
                    try {
                        accessData.put("roles", objectMapper.writeValueAsString(roles));
                    } catch (JsonProcessingException e) {
                        sink.error(new RuntimeException(e));
                    }
                    redisTemplate.opsForHash().putAll(accessKey, accessData);
                    sink.next(Boolean.TRUE.equals(redisTemplate.expire(accessKey, jwtAccessExpiration, TimeUnit.MILLISECONDS)));
                }).onErrorReturn(false);
    }

    boolean registerRefreshToken(String login, String jwtRefreshToken) {
        try {
            redisTemplate.opsForValue().set(TokenType.REFRESH.name() + ":" + login, jwtRefreshToken, jwtRefreshExpiration, TimeUnit.MILLISECONDS);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    Set<String> getRoles(String login) {
        String rolesJson = (String) redisTemplate.opsForHash().get(TokenType.ACCESS.name() + ":" + login, "roles");
        try {
            return objectMapper.readValue(rolesJson, new TypeReference<Set<String>>() {});
        } catch (JsonProcessingException e) {
            return Set.of();
        }
    }

    boolean isRefreshTokenHasNotExpire(String login) {
        Long expirationTimeInMillis = redisTemplate.getExpire(TokenType.REFRESH.name() + ":" + login, TimeUnit.MILLISECONDS);
        if (expirationTimeInMillis == null || expirationTimeInMillis <= 0) {
            return false;
        }
        return System.currentTimeMillis() < expirationTimeInMillis;
    }
}
