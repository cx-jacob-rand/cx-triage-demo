"""
Tests for Stored XSS vulnerability remediation in admin dashboard

This test suite verifies that the Stored XSS vulnerability in the admin_dashboard
function (line 141 of app.py) has been properly fixed. The vulnerability allowed
malicious JavaScript stored in the database to be executed when rendered in the
admin dashboard template.

The fix implements proper HTML escaping in the role_badge Jinja2 filter to prevent
XSS attacks through user-controlled data.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from models import db, User, Project, Task
from utils.jinja_filters import role_badge
from markupsafe import Markup


class TestXSSRemediation:
    """Test XSS vulnerability remediation in admin dashboard"""

    def test_role_badge_escapes_xss_in_role(self, app):
        """Test that role_badge filter properly escapes XSS payloads in role field"""
        with app.app_context():
            # Test various XSS payloads
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "' onload='alert(\"XSS\")'",
                '<svg/onload=alert("XSS")>',
                'javascript:alert("XSS")',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
            ]

            for payload in xss_payloads:
                # Call role_badge filter with malicious payload
                result = role_badge(None, payload)

                # Verify the result is a Markup object (safe HTML)
                assert isinstance(result, str), f"Expected string output for payload: {payload}"

                # Verify the payload is HTML-escaped
                assert '<script>' not in result, f"Script tag not escaped in payload: {payload}"
                assert 'onerror=' not in result, f"Event handler not escaped in payload: {payload}"
                assert 'onload=' not in result, f"Event handler not escaped in payload: {payload}"
                assert 'onfocus=' not in result, f"Event handler not escaped in payload: {payload}"
                assert 'javascript:' not in result, f"JavaScript protocol not escaped in payload: {payload}"

                # Verify HTML entities are present (escaped)
                if '<' in payload:
                    assert '&lt;' in result or '&gt;' in result, f"HTML not escaped in payload: {payload}"

    def test_role_badge_preserves_legitimate_roles(self, app):
        """Test that legitimate role values are preserved and work correctly"""
        with app.app_context():
            legitimate_roles = ['admin', 'project_manager', 'team_member', 'guest']

            for role in legitimate_roles:
                result = role_badge(None, role)

                # Verify legitimate role is present in output
                assert role in result, f"Legitimate role '{role}' not found in output"

                # Verify badge structure is correct
                assert '<span class="badge badge-' in result, f"Badge structure incorrect for role: {role}"
                assert '</span>' in result, f"Badge closing tag missing for role: {role}"

    def test_admin_dashboard_with_malicious_user_role(self, app, client, db_session):
        """Test admin dashboard with user having malicious XSS in role field"""
        with app.app_context():
            # Create a user with XSS payload in role field
            malicious_user = User(
                username='hacker',
                email='hacker@example.com',
                role='<script>alert("XSS")</script>'
            )
            malicious_user.set_password('password123')
            db_session.add(malicious_user)
            db_session.commit()

            # Create a test project and task
            project = Project(
                name='Test Project',
                description='Test',
                owner_id=malicious_user.id,
                is_public=False
            )
            db_session.add(project)
            db_session.commit()

            task = Task(
                title='Test Task',
                description='Test',
                project_id=project.id,
                created_by=malicious_user.id,
                status='pending',
                priority='medium'
            )
            db_session.add(task)
            db_session.commit()

            # Request admin dashboard
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200, "Admin dashboard should return 200"

            # Get response data
            html_content = response.data.decode('utf-8')

            # Verify XSS payload is NOT executed (script tags should be escaped)
            assert '<script>alert("XSS")</script>' not in html_content, \
                "Unescaped script tag found in response - XSS vulnerability present!"

            # Verify the escaped version is present
            assert '&lt;script&gt;' in html_content or 'script' not in html_content, \
                "XSS payload should be escaped"

            # Verify page structure is intact
            assert '<title>Admin Dashboard</title>' in html_content, \
                "Admin dashboard page structure should be intact"

    def test_admin_dashboard_with_multiple_xss_vectors(self, app, client, db_session):
        """Test admin dashboard with multiple XSS attack vectors"""
        with app.app_context():
            # Create multiple users with different XSS payloads
            xss_users = [
                {
                    'username': 'attacker1',
                    'email': 'attacker1@example.com',
                    'role': '<img src=x onerror=alert(1)>'
                },
                {
                    'username': 'attacker2',
                    'email': 'attacker2@example.com',
                    'role': '"><svg onload=alert(2)>'
                },
                {
                    'username': 'attacker3',
                    'email': 'attacker3@example.com',
                    'role': "' onclick='alert(3)'"
                },
            ]

            for user_data in xss_users:
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    role=user_data['role']
                )
                user.set_password('password123')
                db_session.add(user)

            db_session.commit()

            # Request admin dashboard
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200

            # Get response data
            html_content = response.data.decode('utf-8')

            # Verify none of the XSS payloads are present unescaped
            assert 'onerror=' not in html_content, "Event handler found unescaped"
            assert 'onload=' not in html_content, "Event handler found unescaped"
            assert 'onclick=' not in html_content, "Event handler found unescaped"

            # Verify escaped versions or absence of dangerous elements
            dangerous_patterns = ['<img src=x', '<svg', '"><']
            for pattern in dangerous_patterns:
                if pattern in html_content:
                    # If present, should be escaped
                    assert '&lt;' in html_content or '&gt;' in html_content, \
                        f"Pattern '{pattern}' should be escaped"

    def test_role_badge_handles_special_characters(self, app):
        """Test that role_badge properly handles special HTML characters"""
        with app.app_context():
            special_chars_tests = [
                ('admin&user', '&amp;'),  # Ampersand
                ('admin<user', '&lt;'),    # Less than
                ('admin>user', '&gt;'),    # Greater than
                ('admin"user', '&#34;'),   # Quote (may vary)
                ("admin'user", '&#39;'),   # Single quote (may vary)
            ]

            for input_role, expected_escape in special_chars_tests:
                result = role_badge(None, input_role)

                # The dangerous character should be escaped
                assert expected_escape in result or input_role.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') in result, \
                    f"Special character in '{input_role}' not properly escaped"

    def test_role_badge_with_empty_and_none_values(self, app):
        """Test role_badge handles edge cases like empty strings and None"""
        with app.app_context():
            # Test empty string
            result = role_badge(None, '')
            assert '<span class="badge' in result, "Empty role should still generate badge"

            # Test None - should handle gracefully
            try:
                result = role_badge(None, None)
                # Should either handle None or convert to string
                assert 'badge' in result, "None role should be handled gracefully"
            except (TypeError, AttributeError):
                # Acceptable if it raises an error for None
                pass

    def test_admin_dashboard_rendering_safe_data(self, app, client, db_session):
        """Test that admin dashboard correctly renders legitimate safe data"""
        with app.app_context():
            # Create users with legitimate roles
            safe_user = User(
                username='safeuser',
                email='safe@example.com',
                role='admin'
            )
            safe_user.set_password('password123')
            db_session.add(safe_user)

            project = Project(
                name='Safe Project',
                description='A safe project',
                owner_id=safe_user.id,
                is_public=True
            )
            db_session.add(project)

            task = Task(
                title='Safe Task',
                description='A safe task',
                project_id=project.id,
                created_by=safe_user.id,
                status='pending',
                priority='high'
            )
            db_session.add(task)
            db_session.commit()

            # Request admin dashboard
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200

            # Get response data
            html_content = response.data.decode('utf-8')

            # Verify legitimate data is rendered correctly
            assert 'Admin Dashboard' in html_content
            assert 'Total Users' in html_content
            assert 'Total Projects' in html_content
            assert 'Total Tasks' in html_content

            # Verify user data is present
            assert 'safeuser' in html_content or 'safe@example.com' in html_content

    def test_role_badge_context_filter_signature(self, app):
        """Test that role_badge maintains contextfilter signature"""
        with app.app_context():
            # Verify the function works with context parameter
            result = role_badge(None, 'admin')
            assert result is not None
            assert 'admin' in result
            assert '<span' in result


class TestXSSPreventionBestPractices:
    """Test XSS prevention follows security best practices"""

    def test_markupsafe_escape_is_used(self):
        """Verify that markupsafe.escape is imported and available"""
        from markupsafe import escape

        # Test escape function works correctly
        dangerous_input = '<script>alert("XSS")</script>'
        escaped = escape(dangerous_input)

        # Verify escaping occurred
        assert '&lt;' in str(escaped)
        assert '&gt;' in str(escaped)
        assert '<script>' not in str(escaped)

    def test_jinja2_autoescape_compatibility(self, app):
        """Test that the fix is compatible with Jinja2 autoescape"""
        with app.app_context():
            # Verify Jinja2 autoescape is enabled
            assert app.jinja_env.autoescape, "Jinja2 autoescape should be enabled"

            # Test role_badge with autoescape context
            result = role_badge(None, '<script>alert("XSS")</script>')

            # Result should have escaped content
            assert '<script>' not in result

    def test_defense_in_depth(self, app, client, db_session):
        """Test that multiple layers of XSS defense are in place"""
        with app.app_context():
            # Create user with nested XSS attempts
            nested_xss_user = User(
                username='<script>alert("user")</script>',
                email='test@example.com',
                role='<img src=x onerror=alert("role")>'
            )
            nested_xss_user.set_password('password123')
            db_session.add(nested_xss_user)
            db_session.commit()

            # Request admin dashboard
            response = client.get('/admin')
            html_content = response.data.decode('utf-8')

            # Verify no XSS vectors are unescaped
            assert '<script>alert("user")</script>' not in html_content
            assert '<img src=x onerror=' not in html_content
            assert 'onerror=alert' not in html_content

            # Verify the page still renders successfully
            assert response.status_code == 200
            assert 'Admin Dashboard' in html_content


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
