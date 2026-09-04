-- HIGH: expensive aggregation over an existing large table written back to the DB.
CREATE TABLE user_stats (
    user_id  BIGINT PRIMARY KEY,
    events   BIGINT NOT NULL
);

INSERT INTO user_stats (user_id, events)
SELECT user_id, COUNT(*)
FROM events
GROUP BY user_id;
