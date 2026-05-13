# Mock Feed Server

This tiny server is used by the pytest suite and optional Docker Compose profile `test-failover`.

Routes are configured by the `MOCK_FEED_CONFIG` environment variable. It points to a JSON file that maps request paths to responses.
