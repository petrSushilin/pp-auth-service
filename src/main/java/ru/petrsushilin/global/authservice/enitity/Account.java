package ru.petrsushilin.global.authservice.enitity;

import org.springframework.boot.autoconfigure.domain.EntityScan;

import java.util.Set;
import java.util.UUID;

public record Account(UUID uuid, String login, String password, Set<String> roles) {
}
