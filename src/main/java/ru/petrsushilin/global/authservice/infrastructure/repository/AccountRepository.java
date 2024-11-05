package ru.petrsushilin.global.authservice.infrastructure.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import ru.petrsushilin.global.authservice.domain.enitity.Account;

import java.util.Set;
import java.util.UUID;

@Repository
public interface AccountRepository extends ReactiveCrudRepository<Account, UUID> {
    Mono<Set<String>> getRolesByLogin(String login);

    Mono<Account> findByLoginAndPassword(String login, String password);
}
