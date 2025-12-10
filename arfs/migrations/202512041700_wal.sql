CREATE TABLE wal_files
(
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
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
    FOREIGN KEY (file_id) REFERENCES wal_files (id) ON DELETE CASCADE,
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