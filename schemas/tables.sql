CREATE TABLE sms_meeting_log (
    group_number       VARCHAR(64) NOT NULL,
    meeting_number     VARCHAR(64) NOT NULL,
    meeting_ended_at   TIMESTAMP WITH TIME ZONE,
    cycle_id           VARCHAR(64),
    version            VARCHAR(32),
    encrypted_payload  TEXT NOT NULL,
    decrypted_message  TEXT NOT NULL,
    raw_sms            TEXT NOT NULL,
    country            VARCHAR(8),
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (group_number, meeting_number)
);

CREATE TABLE sms_failed_decrypt_log (
    id                SERIAL PRIMARY KEY,
    from_number       VARCHAR(64) NOT NULL,
    to_dsl_number     VARCHAR(64) NOT NULL,
    encrypted_payload TEXT NOT NULL,
    raw_sms           TEXT NOT NULL,
    error_reason      TEXT NOT NULL,
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);