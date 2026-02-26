package dev.slethware.hermez.user;

import lombok.Getter;

@Getter
public enum SubscriptionTier {

    CHELYS("chelys",     1,  0,  0,   100,  1,    LogDetail.BASIC),
    INVENTOR("inventor", 5,  3,  1,   1000, 72,   LogDetail.BASIC),
    PETASOS("petasos",   15, 5,  5,   5000, 720,  LogDetail.FULL),
    TALARIA("talaria",   -1, -1, -1,  -1,   -1,   LogDetail.FULL);

    public enum LogDetail { BASIC, FULL }

    private final String     value;
    private final int        maxTunnels;
    private final int        maxSubdomainReservations;
    private final int        maxCustomDomains;
    private final int        maxRequestLogs;
    private final int        logRetentionHours;
    private final LogDetail  logDetail;

    SubscriptionTier(String value,
                     int maxTunnels,
                     int maxSubdomainReservations,
                     int maxCustomDomains,
                     int maxRequestLogs,
                     int logRetentionHours,
                     LogDetail logDetail) {
        this.value                    = value;
        this.maxTunnels               = maxTunnels;
        this.maxSubdomainReservations = maxSubdomainReservations;
        this.maxCustomDomains         = maxCustomDomains;
        this.maxRequestLogs           = maxRequestLogs;
        this.logRetentionHours        = logRetentionHours;
        this.logDetail                = logDetail;
    }

    public boolean isUnlimitedTunnels() {
        return maxTunnels == -1;
    }

    public boolean isUnlimitedSubdomains() {
        return maxSubdomainReservations == -1;
    }

    public boolean isUnlimitedDomains() {
        return maxCustomDomains == -1;
    }

    public boolean canReplay() {
        return this == PETASOS || this == TALARIA;
    }

    public boolean canExport() {
        return this == TALARIA;
    }

    public static SubscriptionTier fromValue(String value) {
        for (SubscriptionTier tier : values()) {
            if (tier.value.equalsIgnoreCase(value)) {
                return tier;
            }
        }
        throw new IllegalArgumentException("Invalid subscription tier: " + value);
    }
}