package dev.slethware.hermez.domain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;

@Slf4j
@Service
public class DomainVerificationService {

    public String generateVerificationToken() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public String buildTxtRecordName(String domain) {
        return "_hermez." + domain;
    }

    public String buildExpectedTxtValue(String token) {
        return "hermez-verify=" + token;
    }

    public Mono<Boolean> verifyOwnership(String domain, String expectedToken) {
        return Mono.fromCallable(() -> performDnsLookup(domain, expectedToken))
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(Duration.ofSeconds(5))
                .onErrorReturn(false);
    }

    private boolean performDnsLookup(String domain, String expectedToken) {
        String txtName = buildTxtRecordName(domain);
        String expected = buildExpectedTxtValue(expectedToken);
        try {
            Record[] records = new Lookup(txtName, Type.TXT).run();
            if (records == null) {
                return false;
            }
            for (Record record : records) {
                TXTRecord txt = (TXTRecord) record;
                for (String segment : txt.getStrings()) {
                    if (segment.contains(expected)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.debug("DNS lookup failed for {}: {}", txtName, e.getMessage());
            return false;
        }
    }
}