package dev.slethware.hermez.apikey.api;

import java.util.List;

public record ApiKeyListResponse(List<ApiKeyResponse> keys) {}