package ru.petrsushilin.global.authservice.api.handlers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.application.service.AuthService;
import ru.petrsushilin.global.dto.auth.AuthenticationDTO;

@Component
public class AuthenticationHandler {
    private final AuthService authenticationService;

    @Autowired
    public AuthenticationHandler(AuthService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public Mono<ServerResponse> authenticate(ServerRequest serverRequest) {
        Mono<AuthenticationDTO> dtoMono = serverRequest.bodyToMono(AuthenticationDTO.class);

        return dtoMono
                .doOnNext(dto -> {
                    if (dto.login() == null || dto.password() == null) {
                        throw new IllegalArgumentException("Fields must not be empty");
                    }
                })
                .flatMap(dto -> ServerResponse
                        .ok()
                        .bodyValue(authenticationService.authenticate(dto))
                )
                .onErrorResume(error -> ServerResponse
                        .badRequest()
                        .bodyValue("Validation Exception")
                );
    }
}
