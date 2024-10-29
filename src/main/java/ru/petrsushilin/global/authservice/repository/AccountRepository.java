package ru.petrsushilin.global.authservice.repository;

import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.enitity.Account;

import java.util.Set;
import java.util.UUID;

@Repository
public interface AccountRepository extends ReactiveCrudRepository<Account, UUID> {
    Mono<Set<String>> getRolesByLogin(String login);
}
