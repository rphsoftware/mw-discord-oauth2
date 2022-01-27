CREATE TABLE IF NOT EXISTS /*_*/discord_oauth2_users (
    -- User ID
     id int not null primary key,

    -- Module user has selected
    discordId varchar(32) unique not null
) /*$wgDBTableOptions*/;
