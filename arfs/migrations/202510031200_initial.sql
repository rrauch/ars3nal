-- Entities
CREATE TABLE entity
(
    id            INTEGER PRIMARY KEY NOT NULL,

    -- DR: Drive, DS: DriveSignature, FI: File, FO: Folder, SN: Snapshot
    entity_type   TEXT                NOT NULL CHECK (entity_type IN ('DR', 'DS', 'FI', 'FO', 'SN')),

    location      TEXT                NOT NULL CHECK (location LIKE 'ar://item/%' AND LENGTH(location) >= 58),
    block         INTEGER             NOT NULL CHECK (block > 0),

    entity_id     BLOB CHECK (entity_id IS NULL OR (TYPEOF(entity_id) == 'blob' AND
                                                    LENGTH(entity_id) == 16)),

    header        BLOB                NOT NULL CHECK (json_valid(header, 8)),
    metadata      BLOB CHECK (metadata IS NULL OR json_valid(metadata, 8)),

    data_location TEXT CHECK (data_location IS NULL OR (data_location LIKE 'ar://item/%' AND LENGTH(data_location) >= 58)),

    UNIQUE (entity_type, entity_id),

    -- === DRIVE (DR) constraints ===
    CHECK (entity_type != 'DR' OR (
        entity_id IS NOT NULL AND
        metadata IS NOT NULL
        )),

    -- === DRIVE_SIGNATURE (DS) constraints ===
    -- nothing seems mandatory for DS entities

    -- === FOLDER (FO) constraints ===
    CHECK (entity_type != 'FO' OR (
        entity_id IS NOT NULL AND
        metadata IS NOT NULL
        )),

    -- === FILE (FI) constraints ===
    CHECK (entity_type != 'FI' OR (
        entity_id IS NOT NULL AND
        metadata IS NOT NULL AND
        data_location IS NOT NULL
        )),

    -- === SNAPSHOT (SN) constraints ===
    CHECK (entity_type != 'SN' OR (
        entity_id IS NOT NULL
        ))
);

CREATE TRIGGER prevent_entity_updates
    BEFORE UPDATE
    ON entity
BEGIN
    SELECT RAISE(ABORT, 'entity table entries cannot be updated');
END;


-- Config
CREATE TABLE config
(
    drive_id     INTEGER NOT NULL REFERENCES entity (id),
    signature_id INTEGER REFERENCES entity (id),

    name         TEXT    NOT NULL CHECK (LENGTH(name) > 0 AND
                                         LENGTH(name) < 256),
    owner        BLOB    NOT NULL CHECK (TYPEOF(owner) == 'blob' AND
                                         LENGTH(owner) == 32),
    network_id   TEXT    NOT NULL CHECK (LENGTH(network_id) > 0 AND
                                         LENGTH(network_id) < 256)
);

CREATE TRIGGER prevent_multiple_configs
    BEFORE INSERT
    ON config
    WHEN (SELECT COUNT(*)
          FROM config) >= 1
BEGIN
    SELECT RAISE(ABORT, 'Only one config entry allowed');
END;

CREATE TRIGGER prevent_config_deletes
    BEFORE DELETE
    ON config
BEGIN
    SELECT RAISE(ABORT, 'Config cannot be deleted');
END;

CREATE TRIGGER config_drive_entity_type
    BEFORE INSERT
    ON config
BEGIN
    SELECT RAISE(ABORT, 'drive_id must reference a Drive entity')
    WHERE NOT EXISTS (SELECT 1
                      FROM entity
                      WHERE id = NEW.drive_id
                        AND entity_type = 'DR');
END;

CREATE TRIGGER config_drive_entity_type_update
    BEFORE UPDATE
    ON config
BEGIN
    SELECT RAISE(ABORT, 'drive_id must reference a Drive entity')
    WHERE NOT EXISTS (SELECT 1
                      FROM entity
                      WHERE id = NEW.drive_id
                        AND entity_type = 'DR');
END;

CREATE TRIGGER config_signature_entity_type
    BEFORE INSERT
    ON config
    WHEN NEW.signature_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'signature_id must reference a Signature entity')
    WHERE NOT EXISTS (SELECT 1
                      FROM entity
                      WHERE id = NEW.signature_id
                        AND entity_type = 'SN');
END;

CREATE TRIGGER config_signature_entity_type_update
    BEFORE UPDATE
    ON config
    WHEN NEW.signature_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'signature_id must reference a Signature entity')
    WHERE NOT EXISTS (SELECT 1
                      FROM entity
                      WHERE id = NEW.signature_id
                        AND entity_type = 'SN');
END;
