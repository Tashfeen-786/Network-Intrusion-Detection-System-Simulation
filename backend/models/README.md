# Backend models

Request/response validation models live in `backend/schemas.py`; persistent relational models are defined by the auditable SQLite DDL in `backend/database.py`. This directory is retained to mirror an industry layered layout and can hold ORM entities in a future PostgreSQL migration.
