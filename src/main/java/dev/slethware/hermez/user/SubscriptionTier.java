package dev.slethware.hermez.user;

import lombok.Getter;

@Getter
public enum SubscriptionTier {
    CHELYS("chelys",     1,  0),
    INVENTOR("inventor", 5,  3),
    PETASOS("petasos",   15, 5),
    TALARIA("talaria",   -1, -1);

    private final String value;
    private final int maxTunnels;
    private final int maxSubdomainReservations;

    SubscriptionTier(String value, int maxTunnels, int maxSubdomainReservations) {
        this.value                    = value;
        this.maxTunnels               = maxTunnels;
        this.maxSubdomainReservations = maxSubdomainReservations;
    }

    public boolean isUnlimitedTunnels() {
        return maxTunnels == -1;
    }

    public boolean isUnlimited() {
        return maxSubdomainReservations == -1;
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