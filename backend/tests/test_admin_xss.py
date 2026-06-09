"""
Tests for Stored XSS vulnerability remediation in admin dashboard.

This test suite verifies that the admin_dashboard endpoint properly escapes
user-controlled data to prevent Cross-Site Scripting (XSS) attacks.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from models import db, User
from markupsafe import Markup


@pytest.fixture
def app_with_admin_route(app):
    """Add admin route to test app"""
    from app import admin_dashboard
    from utils.jinja_filters import (
        format_datetime, user_display_name, truncate,
        md5_hash, request_id_filter, format_file_size, role_badge
    )

    # Register the admin route
    app.add_url_rule('/admin', 'admin_dashboard', admin_dashboard)

    # Register Jinja2 filters
    app.jinja_env.filters['format_datetime'] = format_datetime
    app.jinja_env.filters['user_display_name'] = user_display_name
    app.jinja_env.filters['truncate'] = truncate
    app.jinja_env.filters['md5_hash'] = md5_hash
    app.jinja_env.filters['request_id_filter'] = request_id_filter
    app.jinja_env.filters['format_file_size'] = format_file_size
    app.jinja_env.filters['role_badge'] = role_badge

    return app


class TestAdminDashboardXSS:
    """Test XSS vulnerability remediation in admin dashboard"""

    def test_xss_in_username_is_escaped(self, app_with_admin_route, db_session):
        """Test that XSS payload in username is properly escaped"""
        # Create user with XSS payload in username
        malicious_user = User(
            username='<script>alert("XSS")</script>',
            email='test@example.com',
            role='team_member'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify the XSS payload is escaped, not executed
            assert '<script>alert("XSS")</script>' not in html_content
            # The escaped version should be present
            assert '&lt;script&gt;' in html_content or 'alert' not in html_content

    def test_xss_in_email_is_escaped(self, app_with_admin_route, db_session):
        """Test that XSS payload in email is properly escaped"""
        # Create user with XSS payload in email
        malicious_user = User(
            username='normaluser',
            email='<img src=x onerror=alert("XSS")>@evil.com',
            role='team_member'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify the XSS payload is escaped
            assert '<img src=x onerror=alert("XSS")>' not in html_content
            assert '&lt;img' in html_content or 'onerror' not in html_content

    def test_xss_in_role_is_escaped(self, app_with_admin_route, db_session):
        """Test that XSS payload in role field is properly escaped

        This is the primary attack vector identified in the vulnerability report.
        The role field flows through role_badge filter with |safe in template.
        """
        # Create user with XSS payload in role
        malicious_user = User(
            username='attacker',
            email='attacker@evil.com',
            role='"><script>alert("Stored XSS")</script><span class="'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify the XSS payload is escaped
            assert '<script>alert("Stored XSS")</script>' not in html_content
            assert '&lt;script&gt;' in html_content or 'Stored XSS' not in html_content

    def test_multiple_xss_payloads_all_escaped(self, app_with_admin_route, db_session):
        """Test that multiple XSS payloads in different fields are all escaped"""
        # Create multiple users with various XSS payloads
        xss_payloads = [
            User(
                username='<svg/onload=alert("XSS1")>',
                email='user1@test.com',
                role='admin'
            ),
            User(
                username='normaluser',
                email='<iframe src="javascript:alert(\'XSS2\')">',
                role='team_member'
            ),
            User(
                username='user3',
                email='user3@test.com',
                role='<img src=x onerror=alert("XSS3")>'
            )
        ]

        for user in xss_payloads:
            user.set_password('password123')
            db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify none of the XSS payloads are present unescaped
            dangerous_patterns = [
                '<svg/onload=alert',
                '<iframe src="javascript:',
                '<img src=x onerror=',
                'XSS1',
                'XSS2',
                'XSS3'
            ]

            for pattern in dangerous_patterns:
                if pattern.startswith('<'):
                    # HTML tags should be escaped
                    assert pattern not in html_content

    def test_legitimate_roles_still_work(self, app_with_admin_route, db_session):
        """Test that legitimate role values are properly displayed"""
        # Create users with legitimate roles
        legitimate_users = [
            User(username='admin1', email='admin@test.com', role='admin'),
            User(username='pm1', email='pm@test.com', role='project_manager'),
            User(username='member1', email='member@test.com', role='team_member')
        ]

        for user in legitimate_users:
            user.set_password('password123')
            db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify legitimate roles are displayed (escaped values should contain the role text)
            assert 'admin' in html_content
            assert 'project_manager' in html_content or 'team_member' in html_content

    def test_html_entities_in_username(self, app_with_admin_route, db_session):
        """Test that HTML entities are properly handled"""
        # Create user with HTML entities
        user = User(
            username='Test&User<>"\'',
            email='test@example.com',
            role='team_member'
        )
        user.set_password('password123')
        db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify special characters are escaped
            # At minimum, angle brackets should be escaped
            assert '&lt;' in html_content or '<>"' not in html_content
            assert '&gt;' in html_content or '<>"' not in html_content

    def test_javascript_protocol_in_role(self, app_with_admin_route, db_session):
        """Test that javascript: protocol in role is escaped"""
        # Create user with javascript: protocol in role
        user = User(
            username='attacker',
            email='attacker@evil.com',
            role='javascript:alert("XSS")'
        )
        user.set_password('password123')
        db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify javascript: protocol is not executable
            # The literal string should be escaped or the dangerous parts removed
            assert 'javascript:alert' not in html_content or 'javascript:' in html_content.replace('javascript:', '')

    def test_event_handler_in_email(self, app_with_admin_route, db_session):
        """Test that event handlers in email field are escaped"""
        # Create user with event handler in email
        user = User(
            username='user',
            email='test@example.com" onload="alert(\'XSS\')',
            role='team_member'
        )
        user.set_password('password123')
        db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify event handler is escaped
            assert 'onload="alert' not in html_content or '&quot;' in html_content

    def test_no_xss_with_empty_fields(self, app_with_admin_route, db_session):
        """Test that empty or null fields don't cause issues"""
        # Create user with minimal data
        user = User(
            username='minimaluser',
            email='minimal@test.com',
            role=None  # Test with None role
        )
        user.set_password('password123')
        db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            # Should not crash or expose vulnerabilities

    def test_reflected_xss_in_mixed_content(self, app_with_admin_route, db_session):
        """Test XSS with mixed legitimate and malicious content"""
        # Create user with partially malicious data
        user = User(
            username='Legitimate User <script>alert(1)</script>',
            email='real@company.com',
            role='admin'
        )
        user.set_password('password123')
        db_session.add(user)
        db_session.commit()

        # Make request to admin dashboard
        with app_with_admin_route.test_client() as client:
            response = client.get('/admin')

            # Verify response is successful
            assert response.status_code == 200
            html_content = response.data.decode('utf-8')

            # Verify legitimate part might be shown but script is escaped
            assert '<script>alert(1)</script>' not in html_content
            # Legitimate part should still be visible (escaped)
            assert 'Legitimate User' in html_content or '&lt;script&gt;' in html_content


class TestEscapingUtility:
    """Test the escaping functionality directly"""

    def test_markupsafe_escape_html_tags(self):
        """Test that markupsafe.escape properly escapes HTML tags"""
        from markupsafe import escape

        malicious = '<script>alert("XSS")</script>'
        escaped = escape(malicious)

        # Verify it's been escaped
        assert '<script>' not in str(escaped)
        assert '&lt;script&gt;' in str(escaped)

    def test_markupsafe_escape_quotes(self):
        """Test that markupsafe.escape properly escapes quotes"""
        from markupsafe import escape

        malicious = '"><script>alert("XSS")</script><"'
        escaped = escape(malicious)

        # Verify quotes and tags are escaped
        assert '><script>' not in str(escaped)
        assert '&quot;' in str(escaped) or '&#34;' in str(escaped)

    def test_markupsafe_escape_ampersands(self):
        """Test that markupsafe.escape properly escapes ampersands"""
        from markupsafe import escape

        text = 'Test & More & Stuff'
        escaped = escape(text)

        # Verify ampersands are escaped
        assert '&amp;' in str(escaped)

    def test_markupsafe_escape_returns_markup(self):
        """Test that escape returns Markup type"""
        from markupsafe import escape, Markup

        text = '<div>Test</div>'
        escaped = escape(text)

        # Verify it returns Markup type
        assert isinstance(escaped, Markup)
        # And that it's been escaped
        assert '&lt;' in str(escaped)
