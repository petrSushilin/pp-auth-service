package ru.petrsushilin.global.authservice.api.routers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import ru.petrsushilin.global.authservice.api.handlers.AuthenticationHandler;

@Configuration
public class AuthenticationRouter {
    private final AuthenticationHandler authenticationHandler;

    public AuthenticationRouter(AuthenticationHandler authenticationHandler) {
        this.authenticationHandler = authenticationHandler;
    }

    @Bean
    public RouterFunction<ServerResponse> authenticationRouter() {
        return RouterFunctions.route(RequestPredicates.POST("/auth"), request -> {
            String IP_ADDRESS = request.remoteAddress()
                    .map(address -> address.getAddress().getHostAddress())
                    .orElse("Undefined IP Address");

            System.out.println("Getting request from IP Address: " + IP_ADDRESS);

            return authenticationHandler.authenticate(request);
        });
    }
}
