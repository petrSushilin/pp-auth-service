package ru.petrsushilin.global.authservice.application.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.infrastructure.repository.AccountRepository;
import ru.petrsushilin.global.dto.auth.AuthenticationDTO;

@Service
public class AuthService {
    private final AccountRepository accountRepository;
    private final JwtService jwtService;

    @Autowired
    public AuthService(AccountRepository accountRepository, JwtService jwtService) {
        this.accountRepository = accountRepository;
        this.jwtService = jwtService;
    }

    public Mono<String> authenticate(AuthenticationDTO authenticationDTO) {
        return accountRepository
                .findByLoginAndPassword(authenticationDTO.login(), authenticationDTO.password())
                .flatMap(account -> jwtService.generate(authenticationDTO.login()))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid login or password")));
    }
}
