package ru.petrsushilin.global.authservice.application.kafka.consumer;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

    @Service
    public class AccountKafkaConsumer {
        @KafkaListener(topics = "auth-topic", groupId = "auth-service")
        public void consumeAccountData(String accountJson) {
        }
    }
