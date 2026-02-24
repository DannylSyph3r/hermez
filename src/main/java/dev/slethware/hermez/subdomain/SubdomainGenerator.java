package dev.slethware.hermez.subdomain;

import org.springframework.stereotype.Component;

import java.util.concurrent.ThreadLocalRandom;

@Component
public class SubdomainGenerator {

    private static final String[] ADJECTIVES = {
            "acid", "agile", "amber", "ancient", "arctic", "arid", "atomic", "azure",
            "bare", "bold", "brave", "bright", "brisk", "broad", "bronze",
            "calm", "chrome", "civic", "clear", "clever", "cold", "coral", "crisp", "cyan",
            "dark", "deep", "deft", "dense", "divine", "dusty",
            "eager", "early", "edgy", "elite", "epic", "even", "exact",
            "faint", "fast", "feral", "fierce", "firm", "flat", "fluid", "fond", "fresh", "frosty", "full",
            "gentle", "giant", "glad", "golden", "grand", "great", "green",
            "hardy", "honest",
            "ideal", "indigo", "inner", "iron",
            "jade", "keen", "kind",
            "large", "late", "lean", "light", "lofty", "loud", "loyal", "lucid", "lunar",
            "magic", "mellow", "mild", "mint", "misty", "mobile", "modern",
            "neat", "nimble", "noble", "north", "novel",
            "open", "orange", "outer",
            "pale", "patient", "peak", "plain", "polar", "prime", "proud", "pure",
            "quick", "quiet",
            "radiant", "rare", "raw", "ready", "real", "rich", "rigid", "royal",
            "safe", "sage", "serene", "sharp", "sheer", "silver", "simple", "sleek",
            "slim", "smart", "soft", "solar", "solid", "sonic", "static", "steady",
            "stern", "still", "stony", "swift",
            "tender", "thick", "thin", "tidal", "timeless", "tiny", "tough", "turbo",
            "ultra", "unique", "urban",
            "vast", "vivid",
            "warm", "wild", "wise", "young", "zealous"
    };

    private static final String[] NOUNS = {
            "acre", "anchor", "anvil", "apex", "arc", "arrow", "ash", "atlas",
            "badge", "beacon", "bear", "birch", "blade", "bloom", "bolt", "boulder",
            "bridge", "brook",
            "canyon", "cape", "cedar", "chain", "cipher", "clay", "clover", "cloud",
            "comet", "coral", "crane", "crater", "creek", "crown", "crystal",
            "dawn", "delta", "dome", "dune",
            "eagle", "echo", "ember", "epoch",
            "fern", "field", "flame", "flint", "fog", "forge", "frost",
            "gale", "gate", "gem", "glacier", "glyph", "granite", "grove",
            "harbor", "hawk", "hearth", "helm", "horizon", "hull",
            "island",
            "jungle",
            "lagoon", "lantern", "laser", "lava", "leaf", "ledge", "legend", "linden", "lynx",
            "maple", "marble", "meadow", "mesa", "meteor", "mist", "moon", "moss", "mountain",
            "nexus", "nova",
            "oak", "oasis", "ocean", "orbit", "otter",
            "peak", "pine", "pixel", "plain", "planet", "plume", "prism", "pulse",
            "quartz",
            "raven", "reef", "relay", "ridge", "river", "rocket", "root", "ruby", "rune",
            "sage", "sail", "sand", "sequoia", "shard", "signal", "slab", "slate",
            "slope", "snow", "spark", "spire", "spring", "spruce", "star", "stone",
            "storm", "stream", "summit", "surge",
            "thorn", "tide", "timber", "titan", "torch", "tower", "trail",
            "vale", "vault", "vector", "vine", "violet",
            "wake", "wave", "willow", "wisp", "wolf",
            "zenith"
    };

    // Generates a random subdomain (adjective-noun-number),

    public String generate() {
        ThreadLocalRandom rng  = ThreadLocalRandom.current();
        String adjective = ADJECTIVES[rng.nextInt(ADJECTIVES.length)];
        String noun      = NOUNS[rng.nextInt(NOUNS.length)];
        int    number    = rng.nextInt(10, 10000); // 10–9999
        return adjective + "-" + noun + "-" + number;
    }
}