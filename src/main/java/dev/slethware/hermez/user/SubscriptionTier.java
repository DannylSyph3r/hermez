package dev.slethware.hermez.user;

import lombok.Getter;

@Getter
public enum SubscriptionTier {
    CHELYS("chelys", 0),
    INVENTOR("inventor", 3),
    PETASOS("petasos", 5),
    TALARIA("talaria", -1);

    private final String value;
    private final int maxSubdomainReservations;

    SubscriptionTier(String value, int maxSubdomainReservations) {
        this.value = value;
        this.maxSubdomainReservations = maxSubdomainReservations;
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