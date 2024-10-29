package ru.petrsushilin.global.authservice.consumer;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.petrsushilin.global.authservice.enitity.Account;

    @Service
    public class AccountKafkaConsumer {
        @KafkaListener(topics = "auth-topic", groupId = "auth-service")
        public void consumeAccountData(String accountJson) {
        }
    }
