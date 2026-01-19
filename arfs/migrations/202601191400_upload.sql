-- previous wal entries are not compatible
-- resetting to last synced state if in WAL mode
DELETE
FROM vfs
WHERE (SELECT state FROM config) = 'W';

INSERT INTO vfs (id, inode_type, perm_type, entity, name, size, last_modified, parent)
SELECT id,
       inode_type,
       'P',
       entity,
       name,
       size,
       last_modified,
       parent
FROM vfs_snapshot
WHERE (SELECT state FROM config) = 'W';

DELETE
FROM wal;

DELETE
FROM vfs_snapshot;

UPDATE config
SET state = 'P';

-- orphaned entity cleanup
DELETE
FROM entity
WHERE id NOT IN (SELECT drive_id
                 FROM config)
  AND entity_type = 'DR';

DELETE
FROM entity
WHERE id NOT IN (SELECT signature_id
                 FROM config)
  AND entity_type = 'SN';

DELETE
FROM entity
WHERE id NOT IN (SELECT entity
                 FROM vfs
                 WHERE entity IS NOT NULL)
  AND id NOT IN (SELECT entity FROM vfs_snapshot)
  AND id NOT IN (SELECT entity FROM wal)
  AND entity_type = 'FI';

DELETE
FROM entity
WHERE id NOT IN (SELECT entity
                 FROM vfs
                 WHERE entity IS NOT NULL)
  AND id NOT IN (SELECT entity FROM vfs_snapshot)
  AND id NOT IN (SELECT entity FROM wal)
  AND id NOT IN (SELECT root_folder_id
                 FROM config)
  AND entity_type = 'FO';

DROP TABLE wal_entity;

CREATE TABLE wal_entity
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    entity_type TEXT                              NOT NULL CHECK (entity_type IN ('FI', 'FO')),
    metadata    BLOB                              NOT NULL CHECK (json_valid(metadata, 8))
);

CREATE TABLE upload
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT      NOT NULL,
    created      TIMESTAMP                              NOT NULL,
    uploaded     TIMESTAMP                              NOT NULL,
    item_type    TEXT CHECK (item_type IN ('TX', 'B'))  NOT NULL,
    item_id      TEXT CHECK (LENGTH(item_id) == 43)     NOT NULL,
    mode         TEXT CHECK (mode IN ('D', 'T'))        NOT NULL,
    data_size    INTEGER CHECK (data_size > 0)          NOT NULL,
    cost         INTEGER CHECK (cost >= 0)              NOT NULL,
    status       TEXT CHECK (status IN ('P', 'S', 'E')) NOT NULL,
    completed    TIMESTAMP,
    block_height INTEGER CHECK (block_height IS NULL OR (block_height > 0 and block_height < 1000000000)),

    CHECK (
        (status == 'P' AND completed IS NULL AND block_height IS NULL) OR
        (status == 'S' AND completed IS NOT NULL AND block_height IS NOT NULL) OR
        (status == 'E' AND completed IS NOT NULL AND block_height IS NULL)
        )
);

ALTER TABLE wal
    ADD COLUMN upload INTEGER REFERENCES upload (id);