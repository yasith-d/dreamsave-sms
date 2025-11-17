CREATE TABLE sms_meeting_log (
    group_number       VARCHAR(64) NOT NULL,
    meeting_number     VARCHAR(64) NOT NULL,
    meeting_ended_at   TIMESTAMP WITH TIME ZONE,
    encrypted_payload  TEXT NOT NULL,
    decrypted_message  TEXT NOT NULL,
    raw_sms            TEXT NOT NULL,
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (group_id, meeting_id)
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
