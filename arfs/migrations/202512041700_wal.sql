CREATE TABLE wal_entity
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    entity_type TEXT                              NOT NULL CHECK (entity_type IN ('FI', 'FO'))
);

CREATE TABLE wal_content
(
    content_hash   BLOB PRIMARY KEY NOT NULL CHECK (TYPEOF(content_hash) == 'blob' AND LENGTH(content_hash) == 32),
    content_length INTEGER          NOT NULL DEFAULT 0 CHECK (content_length >= 0),
    num_chunks     INTEGER                   DEFAULT 0 NOT NULL,
    content        BLOB             NOT NULL CHECK (TYPEOF(content) == 'blob')
);

CREATE TRIGGER prevent_wal_content_update
    BEFORE UPDATE
    ON wal_content
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Updates to content_hash and content columns are not allowed.')
    WHERE OLD.content_hash <> NEW.content_hash
       OR OLD.content <> NEW.content;
END;

CREATE TRIGGER set_wal_content_length_after_insert
    AFTER INSERT
    ON wal_content
    FOR EACH ROW
BEGIN
    UPDATE wal_content
    SET content_length = LENGTH(NEW.content)
    WHERE content_hash = NEW.content_hash;
END;

CREATE TRIGGER delete_wal_content_with_no_chunks
    AFTER UPDATE OF num_chunks
    ON wal_content
    FOR EACH ROW
    WHEN NEW.num_chunks <= 0
BEGIN
    DELETE FROM wal_content WHERE content_hash = NEW.content_hash;
END;

CREATE TABLE wal_chunks
(
    file_id      INTEGER NOT NULL,
    chunk_nr     INTEGER NOT NULL CHECK (chunk_nr >= 0),
    content_hash BLOB    NOT NULL,
    FOREIGN KEY (file_id) REFERENCES wal_entity (id) ON DELETE CASCADE,
    FOREIGN KEY (content_hash) REFERENCES wal_content (content_hash),
    PRIMARY KEY (file_id, chunk_nr)
);

CREATE INDEX idx_wal_chunks_file_id ON wal_chunks (file_id);
CREATE INDEX idx_wal_chunks_chunk_nr ON wal_chunks (chunk_nr);
CREATE INDEX idx_wal_chunks_content_hash ON wal_chunks (content_hash);

CREATE TRIGGER prevent_wal_chunks_update
    BEFORE UPDATE
    ON wal_chunks
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Updates to file_id and chunk_nr columns are not allowed.')
    WHERE OLD.file_id <> NEW.file_id
       OR OLD.chunk_nr <> NEW.chunk_nr;
END;

CREATE TRIGGER increment_wal_content_num_chunks
    AFTER INSERT
    ON wal_chunks
BEGIN
    UPDATE wal_content
    SET num_chunks = num_chunks + 1
    WHERE content_hash = NEW.content_hash;
END;

CREATE TRIGGER decrement_wal_content_num_chunks
    AFTER DELETE
    ON wal_chunks
BEGIN
    UPDATE wal_content
    SET num_chunks = num_chunks - 1
    WHERE content_hash = OLD.content_hash;
END;

CREATE TRIGGER update_wal_content_num_chunks
    AFTER UPDATE OF content_hash
    ON wal_chunks
BEGIN
    UPDATE wal_content
    SET num_chunks = num_chunks - 1
    WHERE content_hash = OLD.content_hash;

    UPDATE wal_content
    SET num_chunks = num_chunks + 1
    WHERE content_hash = NEW.content_hash;
END;

-- Alter vfs table and migrate existing data

-- Drop all triggers related to vfs
DROP TRIGGER vfs_unique_root_inodes;
DROP TRIGGER vfs_unique_root_inodes_update;
DROP TRIGGER vfs_validate_entity_type_on_insert;
DROP TRIGGER vfs_validate_entity_type_on_update;
DROP TRIGGER vfs_prevent_inode_type_change;
DROP TRIGGER vfs_ensure_directory_as_parent_on_insert;
DROP TRIGGER vfs_ensure_directory_as_parent_on_update;
DROP TRIGGER vfs_prevent_self_parent_on_insert;
DROP TRIGGER vfs_prevent_self_parent_on_update;
DROP TRIGGER vfs_prevent_loops_on_update;
DROP TRIGGER vfs_update_inode_path_on_insert;
DROP TRIGGER vfs_update_inode_path_on_update;
DROP TRIGGER vfs_update_inode_path_on_update_recursive;
DROP TRIGGER vfs_capture_deleted_inode_ids;
DROP TRIGGER vfs_capture_updated_inode_ids;
DROP TRIGGER vfs_file_only_proactive_caching_on_insert;
DROP TRIGGER vfs_file_only_proactive_caching_on_update;

-- Drop the view that depends on vfs
DROP VIEW vfs_inode_ancestors;

-- Drop indexes
DROP INDEX idx_vfs_entity;
DROP INDEX idx_vfs_parent;
DROP INDEX idx_vfs_path_cover;

-- Create new vfs table with updated schema
CREATE TABLE vfs_new
(
    id                              INTEGER PRIMARY KEY AUTOINCREMENT       NOT NULL CHECK (id >= 1000 OR id == 2),
    inode_type                      TEXT CHECK (inode_type IN ('FO', 'FI')) NOT NULL,
    perm_type                       TEXT CHECK (perm_type IN ('P', 'W'))    NOT NULL,
    entity                          INTEGER,
    wal_entity                      INTEGER,
    name                            TEXT                                    NOT NULL CHECK (LENGTH(name) > 0
        AND LENGTH(name) <= 255
        AND LENGTH(TRIM(name)) = LENGTH(name)
        AND name NOT LIKE '%/%'),
    size                            INTEGER                                 NOT NULL CHECK (size >= 0),
    last_modified                   TIMESTAMP                               NOT NULL,
    visibility                      TEXT CHECK (visibility IN ('V', 'H'))   NOT NULL DEFAULT 'V',
    parent                          INTEGER CHECK (parent IS NULL OR parent >= 1),
    path                            TEXT                                    NOT NULL DEFAULT '__INVALID__',
    last_proactively_cached_at      TIMESTAMP CHECK (last_proactively_cached_at IS NULL OR
                                                     ((last_proactively_cached_at >= 1577836800 AND
                                                       last_proactively_cached_at < 4733510400))),
    last_proactive_cache_attempt_at TIMESTAMP CHECK (last_proactive_cache_attempt_at IS NULL OR
                                                     ((last_proactive_cache_attempt_at >= 1577836800 AND
                                                       last_proactive_cache_attempt_at < 4733510400))),

    FOREIGN KEY (entity) REFERENCES entity (id) ON DELETE CASCADE,
    FOREIGN KEY (wal_entity) REFERENCES wal_entity (id) ON DELETE CASCADE,
    FOREIGN KEY (parent) REFERENCES vfs_new (id) ON DELETE CASCADE,
    UNIQUE (parent, name),
    CHECK (
        (perm_type = 'P' AND entity IS NOT NULL AND wal_entity IS NULL) OR
        (perm_type = 'W' AND wal_entity IS NOT NULL AND entity IS NULL)
        ),
    CHECK (
        (inode_type = 'FI' AND perm_type = 'P') OR
        (last_proactively_cached_at IS NULL AND last_proactive_cache_attempt_at IS NULL)
        )
);

INSERT INTO sqlite_sequence (name, seq)
SELECT 'vfs_new', seq
FROM sqlite_sequence
WHERE name = 'vfs';

-- Copy data from old table (all existing entries are permanent)
INSERT INTO vfs_new (id, inode_type, perm_type, entity, wal_entity, name, size, last_modified, visibility, parent, path,
                     last_proactively_cached_at, last_proactive_cache_attempt_at)
SELECT id,
       inode_type,
       'P',
       entity,
       NULL,
       name,
       size,
       last_modified,
       visibility,
       parent,
       path,
       last_proactively_cached_at,
       last_proactive_cache_attempt_at
FROM vfs;

-- Drop old table
DROP TABLE vfs;

DELETE FROM sqlite_sequence WHERE name = 'vfs';

-- Rename new table
ALTER TABLE vfs_new
    RENAME TO vfs;

-- Recreate indexes
CREATE INDEX idx_vfs_entity ON vfs (entity);
CREATE INDEX idx_vfs_wal_entity ON vfs (wal_entity);
CREATE INDEX idx_vfs_parent ON vfs (parent);
CREATE INDEX idx_vfs_path_cover ON vfs (path, visibility, inode_type);

-- Recreate the view
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

-- Recreate triggers
CREATE TRIGGER vfs_unique_root_inodes
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NULL
BEGIN
    SELECT RAISE(FAIL, 'Duplicate named inode in vfs root')
    WHERE EXISTS (SELECT 1 FROM vfs WHERE parent IS NULL AND name = NEW.name);
END;

CREATE TRIGGER vfs_unique_root_inodes_update
    BEFORE UPDATE OF name, parent
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NULL
BEGIN
    SELECT RAISE(FAIL, 'Duplicate named inode in vfs root')
    WHERE EXISTS (SELECT 1 FROM vfs WHERE parent IS NULL AND name = NEW.name AND id != NEW.id);
END;

CREATE TRIGGER vfs_validate_entity_type_on_insert_perm
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.perm_type = 'P'
BEGIN
    SELECT RAISE(ABORT, 'VFS inode_type must match entity type')
    WHERE NOT EXISTS (SELECT 1 FROM entity WHERE id = NEW.entity AND entity_type = NEW.inode_type);
END;

CREATE TRIGGER vfs_validate_entity_type_on_update_perm
    BEFORE UPDATE OF entity, inode_type
    ON vfs
    FOR EACH ROW
    WHEN NEW.perm_type = 'P'
BEGIN
    SELECT RAISE(ABORT, 'VFS inode_type must match entity type')
    WHERE NOT EXISTS (SELECT 1 FROM entity WHERE id = NEW.entity AND entity_type = NEW.inode_type);
END;

CREATE TRIGGER vfs_validate_entity_type_on_insert_wal
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.perm_type = 'W'
BEGIN
    SELECT RAISE(ABORT, 'VFS inode_type must match wal_entity type')
    WHERE NOT EXISTS (SELECT 1 FROM wal_entity WHERE id = NEW.wal_entity AND entity_type = NEW.inode_type);
END;

CREATE TRIGGER vfs_validate_entity_type_on_update_wal
    BEFORE UPDATE OF wal_entity, inode_type
    ON vfs
    FOR EACH ROW
    WHEN NEW.perm_type = 'W'
BEGIN
    SELECT RAISE(ABORT, 'VFS inode_type must match wal_entity type')
    WHERE NOT EXISTS (SELECT 1 FROM wal_entity WHERE id = NEW.wal_entity AND entity_type = NEW.inode_type);
END;

CREATE TRIGGER vfs_prevent_inode_type_change
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN OLD.inode_type != NEW.inode_type
BEGIN
    SELECT RAISE(ABORT, 'Cannot change inode_type value');
END;

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

CREATE TRIGGER vfs_ensure_directory_as_parent_on_update
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NOT NULL AND (OLD.parent IS NULL OR NEW.parent != OLD.parent)
BEGIN
    SELECT RAISE(ABORT, 'Parent must be a directory or null')
    FROM vfs
    WHERE id = NEW.parent
      AND inode_type != 'FO';
END;

CREATE TRIGGER vfs_prevent_self_parent_on_insert
    BEFORE INSERT
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent = NEW.id
BEGIN
    SELECT RAISE(ABORT, 'An inode cannot be its own parent');
END;

CREATE TRIGGER vfs_prevent_self_parent_on_update
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent = NEW.id
BEGIN
    SELECT RAISE(ABORT, 'An inode cannot be its own parent');
END;

CREATE TRIGGER vfs_prevent_loops_on_update
    BEFORE UPDATE
    ON vfs
    FOR EACH ROW
    WHEN NEW.parent IS NOT NULL
        AND (OLD.parent IS NULL OR NEW.parent != OLD.parent)
        AND NEW.parent != NEW.id
BEGIN
    SELECT RAISE(ABORT, 'Loop detected in hierarchy - don''t be your own grandparent!')
    WHERE EXISTS (SELECT 1 FROM vfs_inode_ancestors WHERE ancestor = NEW.id AND id = NEW.parent);
END;

CREATE TRIGGER vfs_update_inode_path_on_insert
    AFTER INSERT
    ON vfs
    FOR EACH ROW
BEGIN
    UPDATE vfs SET path = '__RECALCULATE__' WHERE id = NEW.id;
END;

CREATE TRIGGER vfs_update_inode_path_on_update
    AFTER UPDATE OF name, parent
    ON vfs
    FOR EACH ROW
    WHEN OLD.name != NEW.name
        OR OLD.parent IS NULL AND NEW.parent IS NOT NULL
        OR OLD.parent IS NOT NULL AND NEW.parent IS NULL
        OR OLD.parent != NEW.parent
BEGIN
    UPDATE vfs SET path = '__RECALCULATE__' WHERE id = NEW.id;
END;

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

    UPDATE vfs SET path = '__RECALCULATE__' WHERE parent = NEW.id AND id != NEW.id;
END;

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
