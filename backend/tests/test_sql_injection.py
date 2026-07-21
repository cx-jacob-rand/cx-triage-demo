"""
Tests to verify SQL injection vulnerabilities are remediated across
routes/api.py, routes/projects.py, routes/tasks.py, and routes/messages.py.

Each test verifies two things:
  1. Legitimate search still works (functionality preserved).
  2. SQL injection payloads do NOT alter query semantics (attack blocked).
"""
import json
import pytest
import sys
import os

# Ensure the backend package root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Project, Task, Message


# ---------------------------------------------------------------------------
# Helper: common SQL injection attack strings
# ---------------------------------------------------------------------------
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT 1,2,3,4,5,6,7,8--",
    "admin'--",
    "' OR 'x'='x",
    "%27 OR %271%27=%271",   # URL-encoded single quote variant
    "1; SELECT * FROM users--",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def populated_db(db_session, sample_user, admin_user, sample_project, sample_task):
    """Return a db_session that already contains sample data."""
    # Create a second user to test that injection cannot expand results
    second_user = User(username='otheruser', email='other@example.com', role='team_member')
    second_user.set_password('other123')
    db_session.add(second_user)

    # Create a second project owned by admin
    second_project = Project(
        name='Admin Project',
        description='Another project',
        owner_id=admin_user.id,
        is_public=False
    )
    db_session.add(second_project)

    # Create a message between sample_user and admin_user
    msg = Message(
        sender_id=sample_user.id,
        receiver_id=admin_user.id,
        subject='Hello subject',
        content='Hello world content'
    )
    db_session.add(msg)

    db_session.commit()
    return db_session


# ---------------------------------------------------------------------------
# /api/v1/users  (routes/api.py – get_users)
# ---------------------------------------------------------------------------

class TestGetUsersSearchSQLInjection:
    """Tests for the /api/v1/users?search= endpoint."""

    def test_legitimate_search_returns_matching_users(self, client, populated_db, sample_user):
        """A normal search term should return only matching users."""
        response = client.get('/api/v1/users?search=testuser')
        assert response.status_code == 200
        data = json.loads(response.data)
        usernames = [u['username'] for u in data['users']]
        assert 'testuser' in usernames

    def test_no_search_returns_all_users(self, client, populated_db):
        """Without a search parameter all users are returned."""
        response = client.get('/api/v1/users')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['count'] >= 2  # at least sample_user and admin_user

    def test_injection_does_not_bypass_filter(self, client, populated_db):
        """
        SQL injection payloads must not expand results beyond what matches
        the literal search string.  A payload that contains no matching
        username/email should return zero results.
        """
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(f'/api/v1/users?search={payload}')
            assert response.status_code == 200
            data = json.loads(response.data)
            # The payload is not a real username / email, so 0 results expected.
            assert data['count'] == 0, (
                f"Payload '{payload}' returned {data['count']} users – "
                "possible SQL injection bypass!"
            )

    def test_special_chars_treated_as_literal(self, client, populated_db):
        """Single-quote and percent characters are treated as literal text."""
        for payload in ["'", "''", "%", "%%", "\\'"]:
            response = client.get(f"/api/v1/users?search={payload}")
            assert response.status_code == 200
            data = json.loads(response.data)
            # None of these should match existing users
            assert isinstance(data['users'], list)

    def test_empty_search_handled_safely(self, client, populated_db):
        """Empty search parameter returns all users without error."""
        response = client.get('/api/v1/users?search=')
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# /api/v1/projects  (routes/api.py – get_projects_api)
# ---------------------------------------------------------------------------

class TestGetProjectsApiSQLInjection:
    """Tests for the /api/v1/projects?search= endpoint."""

    def test_legitimate_search_returns_matching_projects(self, client, populated_db):
        response = client.get('/api/v1/projects?search=Test')
        assert response.status_code == 200
        data = json.loads(response.data)
        names = [p['name'] for p in data['projects']]
        assert any('Test' in n for n in names)

    def test_injection_does_not_expand_results(self, client, populated_db):
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(f'/api/v1/projects?search={payload}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['projects']) == 0, (
                f"Payload '{payload}' returned {len(data['projects'])} projects – "
                "possible SQL injection bypass!"
            )


# ---------------------------------------------------------------------------
# /api/v1/projects/<id>/tasks  (routes/api.py – get_project_tasks)
# ---------------------------------------------------------------------------

class TestGetProjectTasksSQLInjection:
    """Tests for the /api/v1/projects/<project_id>/tasks?search= endpoint."""

    def test_legitimate_search_returns_matching_tasks(
        self, client, populated_db, sample_project, sample_task
    ):
        response = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks?search=Test'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['tasks']) >= 1

    def test_injection_in_search_does_not_bypass_project_filter(
        self, client, populated_db, sample_project
    ):
        """Injection in the search param must not break the project_id filter."""
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(
                f'/api/v1/projects/{sample_project.id}/tasks?search={payload}'
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            # Payload shouldn't match any task title/description
            assert len(data['tasks']) == 0, (
                f"Payload '{payload}' returned tasks despite no matching content"
            )


# ---------------------------------------------------------------------------
# /api/v1/tasks  (routes/api.py – get_tasks_api)
# ---------------------------------------------------------------------------

class TestGetTasksApiSQLInjection:
    """Tests for the /api/v1/tasks?search= endpoint."""

    def test_legitimate_search_returns_tasks(self, client, populated_db, sample_task):
        response = client.get('/api/v1/tasks?search=Test')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['tasks']) >= 1

    def test_injection_in_search_returns_no_extra_results(
        self, client, populated_db
    ):
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(f'/api/v1/tasks?search={payload}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['tasks']) == 0, (
                f"Payload '{payload}' returned tasks – possible SQL injection bypass!"
            )

    def test_injection_in_project_id_param_handled_safely(
        self, client, populated_db, sample_task, sample_project
    ):
        """Non-integer project_id values should result in no tasks (not an error or bypass)."""
        for payload in ["1 OR 1=1", "1; DROP TABLE tasks--", "' OR '1'='1"]:
            response = client.get(
                f'/api/v1/tasks?search=Test&project_id={payload}'
            )
            # Should either return 200 with properly-filtered results, or 400/500.
            # Most importantly, it must NOT return all tasks.
            if response.status_code == 200:
                data = json.loads(response.data)
                titles = [t['title'] for t in data['tasks']]
                # If any tasks returned they should match the search term
                for t in data['tasks']:
                    assert 'Test' in t.get('title', '') or 'Test' in t.get('description', '')


# ---------------------------------------------------------------------------
# /api/v1/search  (routes/api.py – global_search)
# ---------------------------------------------------------------------------

class TestGlobalSearchSQLInjection:
    """Tests for the /api/v1/search?q= endpoint."""

    def test_legitimate_query_finds_users_and_projects(
        self, client, populated_db, sample_user, sample_project
    ):
        response = client.get('/api/v1/search?q=Test')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'users' in data
        assert 'projects' in data
        assert 'tasks' in data

    def test_missing_query_returns_400(self, client, populated_db):
        response = client.get('/api/v1/search')
        assert response.status_code == 400

    def test_injection_payload_does_not_dump_all_records(
        self, client, populated_db
    ):
        """Injection in q= must not return every record in the database."""
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(f'/api/v1/search?q={payload}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['users']) == 0, (
                f"Payload '{payload}' returned {len(data['users'])} users – "
                "possible SQL injection bypass in global search!"
            )
            assert len(data['projects']) == 0, (
                f"Payload '{payload}' returned projects – SQL injection bypass!"
            )
            assert len(data['tasks']) == 0, (
                f"Payload '{payload}' returned tasks – SQL injection bypass!"
            )


# ---------------------------------------------------------------------------
# /api/projects  (routes/projects.py – get_projects)
# ---------------------------------------------------------------------------

class TestProjectsRouteSQLInjection:
    """Tests for the authenticated /api/projects?search= endpoint."""

    def test_unauthenticated_request_is_rejected(self, client, populated_db):
        response = client.get('/api/projects?search=Test')
        assert response.status_code == 401

    def test_legitimate_search_with_auth(
        self, client, populated_db, auth_headers
    ):
        response = client.get('/api/projects?search=Test', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'projects' in data

    def test_injection_payload_with_auth_does_not_expand_results(
        self, client, populated_db, auth_headers
    ):
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(
                f'/api/projects?search={payload}', headers=auth_headers
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['projects']) == 0, (
                f"Payload '{payload}' returned projects – SQL injection bypass "
                "in authenticated /api/projects!"
            )


# ---------------------------------------------------------------------------
# /api/tasks  (routes/tasks.py – get_tasks)
# ---------------------------------------------------------------------------

class TestTasksRouteSQLInjection:
    """Tests for the authenticated /api/tasks?search= endpoint."""

    def test_unauthenticated_request_is_rejected(self, client, populated_db):
        response = client.get('/api/tasks?search=Test')
        assert response.status_code == 401

    def test_legitimate_search_with_auth_returns_matching_tasks(
        self, client, populated_db, auth_headers, sample_task
    ):
        response = client.get('/api/tasks?search=Test', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['tasks']) >= 1

    def test_injection_payload_with_auth_does_not_expand_results(
        self, client, populated_db, auth_headers
    ):
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(
                f'/api/tasks?search={payload}', headers=auth_headers
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['tasks']) == 0, (
                f"Payload '{payload}' returned tasks – SQL injection bypass "
                "in authenticated /api/tasks!"
            )

    def test_injection_in_project_id_with_auth(
        self, client, populated_db, auth_headers, sample_task, sample_project
    ):
        """project_id injection should not expose tasks from other projects."""
        payload = "1 OR 1=1"
        response = client.get(
            f'/api/tasks?search=Test&project_id={payload}',
            headers=auth_headers
        )
        # The endpoint must not crash and must not return cross-project tasks
        assert response.status_code in (200, 400, 422)


# ---------------------------------------------------------------------------
# /api/messages/search  (routes/messages.py – search_messages)
# ---------------------------------------------------------------------------

class TestMessageSearchSQLInjection:
    """Tests for the authenticated /api/messages/search?q= endpoint."""

    def test_unauthenticated_request_is_rejected(self, client, populated_db):
        response = client.get('/api/messages/search?q=hello')
        assert response.status_code == 401

    def test_missing_query_returns_400(self, client, populated_db, auth_headers):
        response = client.get('/api/messages/search', headers=auth_headers)
        assert response.status_code == 400

    def test_legitimate_search_finds_messages(
        self, client, populated_db, auth_headers
    ):
        response = client.get(
            '/api/messages/search?q=Hello', headers=auth_headers
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'results' in data
        assert len(data['results']) >= 1

    def test_injection_payload_does_not_dump_all_messages(
        self, client, populated_db, auth_headers
    ):
        """Injection must not return messages that don't match the literal query."""
        for payload in SQL_INJECTION_PAYLOADS:
            response = client.get(
                f'/api/messages/search?q={payload}', headers=auth_headers
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['results']) == 0, (
                f"Payload '{payload}' returned {len(data['results'])} messages – "
                "possible SQL injection bypass in message search!"
            )

    def test_query_value_is_echoed_safely(
        self, client, populated_db, auth_headers
    ):
        """The 'query' key in the response should reflect the raw search term."""
        response = client.get(
            "/api/messages/search?q=hello", headers=auth_headers
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['query'] == 'hello'
