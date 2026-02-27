package dev.slethware.hermez.requestinspection;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("request_logs")
public class RequestLog {

    @Id
    private UUID    id;
    private String  tunnelId;
    private UUID    userId;
    private String  requestId;
    private String  method;
    private String  path;
    private String  queryString;
    private String  requestHeaders;
    private byte[]  requestBody;
    private boolean requestBodyTruncated;
    private int     requestSize;
    private String  clientIp;
    private Integer statusCode;
    private String  responseHeaders;
    private byte[]  responseBody;
    private boolean responseBodyTruncated;
    private Integer responseSize;
    private Instant startedAt;
    private Instant completedAt;
    private Integer durationMs;
    private String  status;
    private String  errorMessage;
    private UUID    parentRequestId;
    private String  logDetail;
}