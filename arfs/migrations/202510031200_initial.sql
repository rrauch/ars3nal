-- Entities
CREATE TABLE entity
(
    id            INTEGER PRIMARY KEY NOT NULL,

    -- DR: Drive, DS: DriveSignature, FI: File, FO: Folder, SN: Snapshot
    entity_type   TEXT                NOT NULL CHECK (entity_type IN ('DR', 'DS', 'FI', 'FO', 'SN')),

    location      TEXT                NOT NULL CHECK (location LIKE 'ar://%' AND LENGTH(location) >= 47),
    block         INTEGER             NOT NULL CHECK (block > 0 AND block < 1000000000),

    entity_id     BLOB CHECK (entity_id IS NULL OR (TYPEOF(entity_id) == 'blob' AND
                                                    LENGTH(entity_id) == 16)),

    header        BLOB                NOT NULL CHECK (json_valid(header, 8)),
    metadata      BLOB CHECK (metadata IS NULL OR json_valid(metadata, 8)),

    data_location TEXT CHECK (data_location IS NULL OR (data_location LIKE 'ar://%' AND LENGTH(data_location) >= 47)),

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

CREATE TRIGGER entity_prevent_updates
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

CREATE INDEX idx_config_drive_id ON config (drive_id);
CREATE INDEX idx_config_signature_id ON config (signature_id);

CREATE TRIGGER config_prevent_multiple
    BEFORE INSERT
    ON config
    WHEN (SELECT COUNT(*)
          FROM config) >= 1
BEGIN
    SELECT RAISE(ABORT, 'Only one config entry allowed');
END;

CREATE TRIGGER config_prevent_deletes
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

-- VFS
CREATE TABLE vfs
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT       NOT NULL CHECK (id >= 1000 OR id == 2),
    inode_type    TEXT CHECK (inode_type IN ('FO', 'FI')) NOT NULL,
    entity        INTEGER                                 NOT NULL,
    name          TEXT                                    NOT NULL CHECK (LENGTH(name) > 0
        AND LENGTH(name) <= 255
        AND LENGTH(TRIM(name)) = LENGTH(name)
        AND name NOT LIKE '%/%'),
    size          INTEGER                                 NOT NULL CHECK (size >= 0),
    last_modified TIMESTAMP                               NOT NULL,
    visibility    TEXT CHECK (visibility IN ('V', 'H'))   NOT NULL DEFAULT 'V',
    parent        INTEGER CHECK (parent IS NULL OR parent >= 1),
    path          TEXT                                    NOT NULL DEFAULT '__INVALID__',
    FOREIGN KEY (entity) REFERENCES entity (id) ON DELETE CASCADE,
    FOREIGN KEY (parent) REFERENCES vfs (id) ON DELETE CASCADE,
    UNIQUE (parent, name)
);

CREATE INDEX idx_vfs_entity ON vfs (entity);
CREATE INDEX idx_vfs_parent ON vfs (parent);

-- Ensure the vfs id sequence starts at 1000
INSERT INTO sqlite_sequence (name, seq)
VALUES ('vfs', 999);

-- UNIQUE does not work as expected if there are NULL values involved
CREATE TRIGGER vfs_unique_root_inodes
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NULL
BEGIN
    SELECT RAISE(FAIL, 'Duplicate named inode in vfs root')
    WHERE EXISTS (SELECT 1
                  FROM vfs
                  WHERE parent IS NULL
                    AND name = NEW.name);
END;

CREATE TRIGGER vfs_unique_root_inodes_update
    BEFORE UPDATE OF name, parent
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NULL
BEGIN
    SELECT RAISE(FAIL, 'Duplicate named inode in vfs root')
    WHERE EXISTS (SELECT 1
                  FROM vfs
                  WHERE parent IS NULL
                    AND name = NEW.name
                    AND id != NEW.id);
END;

-- Ensure VFS inode type matches entity type on INSERT
CREATE TRIGGER vfs_validate_entity_type_on_insert
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'VFS inode_type must match entity type')
    WHERE NOT EXISTS (SELECT 1
                      FROM entity
                      WHERE id = NEW.entity
                        AND entity_type = NEW.inode_type);
END;

-- Ensure VFS inode type matches entity type on UPDATE
CREATE TRIGGER vfs_validate_entity_type_on_update
    BEFORE UPDATE OF entity, inode_type
    ON vfs
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'VFS inode_type must match entity type')
    WHERE NOT EXISTS (SELECT 1
                      FROM entity
                      WHERE id = NEW.entity
                        AND entity_type = NEW.inode_type);
END;

-- Prevent changing the inode_type of inodes
CREATE TRIGGER vfs_prevent_inode_type_change
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN OLD.inode_type != NEW.inode_type
BEGIN
    SELECT RAISE(ABORT, 'Cannot change inode_type value');
END;

-- Ensure only directories can be parents (on insert)
CREATE TRIGGER vfs_ensure_directory_as_parent_on_insert
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'Parent must be a directory or null')
    FROM vfs
    WHERE id = NEW.parent
      AND inode_type != 'FO';
END;

-- Ensure only directories can be parents (on update)
CREATE TRIGGER vfs_ensure_directory_as_parent_on_update
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NOT NULL
        AND (OLD.parent IS NULL OR NEW.parent != OLD.parent)
BEGIN
    SELECT RAISE(ABORT, 'Parent must be a directory or null')
    FROM vfs
    WHERE id = NEW.parent
      AND inode_type != 'FO';
END;

-- Prevent an inode from becoming its own parent (on insert)
CREATE TRIGGER vfs_prevent_self_parent_on_insert
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent = NEW.id
BEGIN
    SELECT RAISE(ABORT, 'An inode cannot be its own parent');
END;

-- Prevent an inode from becoming its own parent (on update)
CREATE TRIGGER vfs_prevent_self_parent_on_update
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent = NEW.id
BEGIN
    SELECT RAISE(ABORT, 'An inode cannot be its own parent');
END;

-- Make sure an inode cannot become its own grandparent

-- SQLite does not currently support CTEs within triggers, so this view is
-- created to recursively resolve all ancestors of an inode
CREATE VIEW vfs_inode_ancestors AS
WITH RECURSIVE vfs_ancestor_path(id, ancestor) AS (SELECT id, parent
                                                   FROM vfs
                                                   WHERE parent IS NOT NULL
                                                   UNION ALL
                                                   SELECT o.id, a.ancestor
                                                   FROM vfs o
                                                            JOIN vfs_ancestor_path a ON o.parent = a.id)
SELECT id, ancestor
FROM vfs_ancestor_path;

-- Prevent loops in the parent-child relationships
CREATE TRIGGER vfs_prevent_loops_on_update
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NOT NULL
        AND (OLD.parent IS NULL OR NEW.parent != OLD.parent)
        AND NEW.parent != NEW.id
BEGIN
    SELECT RAISE(ABORT, 'Loop detected in hierarchy - don''t be your own grandparent!')
    WHERE EXISTS (SELECT 1
                  FROM vfs_inode_ancestors
                  WHERE ancestor = NEW.id
                    AND id = NEW.parent);
END;

-- An inode's path is always updated automatically.

-- Mark the inode path for recalculation on insert
CREATE TRIGGER vfs_update_inode_path_on_insert
    AFTER INSERT
    ON vfs
    FOR EACH ROW
BEGIN
    UPDATE vfs
    SET path = '__RECALCULATE__'
    WHERE id = NEW.id;
END;

-- Mark the inode path for recalculation if name or parent changes
CREATE TRIGGER vfs_update_inode_path_on_update
    AFTER UPDATE OF name, parent
    ON vfs
    FOR EACH ROW
    WHEN OLD.name != NEW.name
        OR OLD.parent IS NULL AND NEW.parent IS NOT NULL
        OR OLD.parent IS NOT NULL AND NEW.parent IS NULL
        OR OLD.parent != NEW.parent
BEGIN
    UPDATE vfs
    SET path = '__RECALCULATE__'
    WHERE id = NEW.id;
END;

-- Recursively update the paths of marked objects
CREATE TRIGGER vfs_update_inode_path_on_update_recursive
    AFTER UPDATE OF path
    ON vfs
    FOR EACH ROW
    WHEN NEW.path = '__RECALCULATE__'
BEGIN
    UPDATE vfs
    SET path = (SELECT CASE
                           WHEN NEW.parent IS NULL THEN '/' ||
                                                        CASE
                                                            WHEN NEW.inode_type = 'FO' THEN NEW.name || '/'
                                                            ELSE NEW.name
                                                            END
                           ELSE (SELECT path FROM vfs WHERE id = NEW.parent) ||
                                CASE
                                    WHEN NEW.inode_type = 'FO' THEN NEW.name || '/'
                                    ELSE NEW.name
                                    END
                           END)
    WHERE id = NEW.id;

    UPDATE vfs
    SET path = '__RECALCULATE__'
    WHERE parent = NEW.id
      AND id != NEW.id;
END;

-- A temp table to capture affected object ids
CREATE TABLE vfs_affected_inodes
(
    id INTEGER NOT NULL
);

CREATE TRIGGER vfs_capture_deleted_inode_ids
    AFTER DELETE
    ON vfs
BEGIN
    INSERT INTO vfs_affected_inodes (id) VALUES (OLD.id);
END;

CREATE TRIGGER vfs_capture_updated_inode_ids
    AFTER UPDATE
    ON vfs
BEGIN
    INSERT INTO vfs_affected_inodes (id) VALUES (OLD.id);
END;

-- Sync
CREATE TABLE sync_log
(
    start_time   TIMESTAMP NOT NULL PRIMARY KEY CHECK (start_time >= 1577836800 AND start_time < 4733510400), -- 2020-01-01 to 2120-01-01 UTC,
    duration_ms  INTEGER   NOT NULL CHECK (duration_ms >= 0 AND duration_ms < 2592000000),
    result       TEXT      NOT NULL CHECK (result IN ('S', 'E')),                                             -- Success or Error
    insertions   INTEGER CHECK (insertions IS NULL OR insertions >= 0),
    deletions    INTEGER CHECK (deletions IS NULL OR deletions >= 0),
    block_height INTEGER CHECK (block_height IS NULL OR (block_height > 0 and block_height < 1000000000)),
    error        TEXT CHECK (error IS NULL OR LENGTH(error) <= 255),

    -- === Success constraints ===
    CHECK (result != 'S' OR (
        insertions IS NOT NULL AND
        deletions IS NOT NULL AND
        block_height IS NOT NULL AND
        error IS NULL
        )),

    -- === Error constraints ===
    CHECK (result != 'E' OR (
        insertions IS NULL AND
        deletions IS NULL AND
        error IS NOT NULL
        ))
);

-- GC - keep max 1000 entries, discard the rest
CREATE TRIGGER sync_log_gc
    AFTER INSERT
    ON sync_log
BEGIN
    DELETE
    FROM sync_log
    WHERE start_time IN (SELECT start_time
                         FROM sync_log
                         ORDER BY start_time DESC
                         LIMIT -1 OFFSET 1000);
END;

-- Ensure the most recent log entry is never deleted
CREATE TRIGGER sync_log_protect_latest
    BEFORE DELETE
    ON sync_log
BEGIN
    SELECT RAISE(ABORT, 'Cannot delete the most recent entry')
    WHERE OLD.start_time = (SELECT MAX(start_time) FROM sync_log);
END;

CREATE TRIGGER sync_log_prevent_updates
    BEFORE UPDATE
    ON sync_log
BEGIN
    SELECT RAISE(ABORT, 'sync_log table entries cannot be updated');
END;
