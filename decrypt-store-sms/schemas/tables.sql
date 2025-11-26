CREATE TABLE sms_meeting_log (
    meeting_id         VARCHAR(64) PRIMARY KEY,
    group_id           VARCHAR(64),
    meeting_time       BIGINT,
    version            VARCHAR(64),
    encrypted_payload  TEXT NOT NULL,
    decrypted_message  TEXT NOT NULL,
    raw_sms            TEXT NOT NULL,
    country            VARCHAR(8),
    from_number        VARCHAR(64) NOT NULL,
    to_dsl_number      VARCHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sms_failed_decrypt_log (
    id                SERIAL PRIMARY KEY,
    from_number       VARCHAR(64) NOT NULL,
    to_dsl_number     VARCHAR(64) NOT NULL,
    raw_sms           TEXT NOT NULL,
    error_reason      TEXT NOT NULL,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);