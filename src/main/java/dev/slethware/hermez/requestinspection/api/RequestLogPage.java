package dev.slethware.hermez.requestinspection.api;

import java.util.List;

public record RequestLogPage(
        List<RequestLogResponse> requests,
        int page,
        int size,
        long total
) {}