package ru.petrsushilin.global.authservice.domain.enitity;

import java.util.Set;
import java.util.UUID;

public record Account(UUID uuid, String login, String password, Set<String> roles) {
}
