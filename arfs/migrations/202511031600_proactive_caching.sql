-- Add a column to track the last successful proactive caching of the file's data.
ALTER TABLE vfs
    ADD COLUMN last_proactively_cached_at TIMESTAMP CHECK (last_proactively_cached_at IS NULL OR
                                                           ((last_proactively_cached_at >= 1577836800 AND
                                                             last_proactively_cached_at < 4733510400)));

-- Add a column to track the last attempt to proactively cache the file's data, regardless of success.
ALTER TABLE vfs
    ADD COLUMN last_proactive_cache_attempt_at TIMESTAMP CHECK (last_proactive_cache_attempt_at IS NULL OR
                                                                ((last_proactive_cache_attempt_at >= 1577836800 AND
                                                                  last_proactive_cache_attempt_at < 4733510400)));

-- Ensure that only files can have proactive caching timestamps upon insertion.
CREATE TRIGGER vfs_file_only_proactive_caching_on_insert
    BEFORE INSERT
    ON vfs
    WHEN NEW.inode_type != 'FI' AND
         (NEW.last_proactively_cached_at IS NOT NULL OR NEW.last_proactive_cache_attempt_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'Proactive cache timestamps can only be set for files (inode_type = ''FI'')');
END;

-- Ensure that only files can have proactive caching timestamps upon update.
CREATE TRIGGER vfs_file_only_proactive_caching_on_update
    BEFORE UPDATE
    ON vfs
    WHEN NEW.inode_type != 'FI' AND
         (NEW.last_proactively_cached_at IS NOT NULL OR NEW.last_proactive_cache_attempt_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'Proactive cache timestamps can only be set for files (inode_type = ''FI'')');
END;
