CREATE TABLE request_logs (
                              id                       UUID                     PRIMARY KEY DEFAULT gen_random_uuid(),
                              tunnel_id                VARCHAR(100)             NOT NULL,
                              user_id                  UUID                     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                              request_id               VARCHAR(36)              NOT NULL,
                              method                   VARCHAR(10)              NOT NULL,
                              path                     TEXT                     NOT NULL,
                              query_string             TEXT,
                              request_headers          JSONB,
                              request_body             BYTEA,
                              request_body_truncated   BOOLEAN                  NOT NULL DEFAULT FALSE,
                              request_size             INTEGER                  NOT NULL DEFAULT 0,
                              client_ip                VARCHAR(45),
                              status_code              SMALLINT,
                              response_headers         JSONB,
                              response_body            BYTEA,
                              response_body_truncated  BOOLEAN                  NOT NULL DEFAULT FALSE,
                              response_size            INTEGER,
                              started_at               TIMESTAMP WITH TIME ZONE NOT NULL,
                              completed_at             TIMESTAMP WITH TIME ZONE,
                              duration_ms              INTEGER,
                              status                   VARCHAR(20)              NOT NULL DEFAULT 'pending',
                              error_message            TEXT,
                              parent_request_id        UUID                     REFERENCES request_logs(id),
                              log_detail               VARCHAR(10)              NOT NULL DEFAULT 'basic',

                              CONSTRAINT request_logs_status_check
                                  CHECK (status IN ('pending', 'completed', 'timeout', 'error')),
                              CONSTRAINT request_logs_log_detail_check
                                  CHECK (log_detail IN ('basic', 'full'))
);

CREATE INDEX idx_request_logs_user_id        ON request_logs(user_id);
CREATE INDEX idx_request_logs_tunnel_started ON request_logs(tunnel_id, started_at DESC);