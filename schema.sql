create table track (
    -- Filesystem / ID info
    raw_path text,
    parent_path text,
    checksum bytea,

    -- Music tag info
    tag_title text,
    tag_artist text,
    tag_album text,
    tag_year integer,
    tag_comment text,
    tag_track integer,
    tag_genre text,

    unique(checksum)
);

create table image (
    -- Filesystem / ID info
    raw_path text,
    parent_path text,
    checksum bytea,

    unique(checksum)
);
