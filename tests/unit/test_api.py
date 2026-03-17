#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise NGFW - Unit Tests for REST API

Tests for:
- Authentication (login, JWT tokens)
- Protected endpoint authorization
- Admin role requirements
- Rate limiting behavior
- CORS configuration
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.rest.main import app, _hash_password, _verify_password, SECRET_KEY, ALGORITHM
from system.database.database import DatabaseManager

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    db = DatabaseManager('sqlite:///:memory:')
    db.initialize()
    db.add_default_users(_hash_password("admin123"), _hash_password("operator123"))
    
    class MockNGFW:
        def __init__(self):
            self.db = db
            self.ha_manager = None
            self.health_checker = MagicMock()
            
    app.state.ngfw = MockNGFW()
    app.state.ngfw_app = app.state.ngfw
    
    yield
    db.close()

@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    """Get admin JWT token"""
    response = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    return None


@pytest.fixture
def operator_token(client):
    """Get operator JWT token"""
    response = client.post("/api/v1/auth/login", json={
        "username": "operator",
        "password": "operator123"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    return None


# ==================== Password Hashing Tests ====================

class TestPasswordHashing:
    """Test bcrypt password hashing"""

    def test_hash_password(self):
        """Test password hashing produces a hash"""
        hashed = _hash_password("test_password")
        assert hashed is not None
        assert hashed != "test_password"
        assert hashed.startswith("$2")  # bcrypt prefix

    def test_verify_correct_password(self):
        """Test verifying a correct password"""
        hashed = _hash_password("my_secret")
        assert _verify_password("my_secret", hashed) is True

    def test_verify_wrong_password(self):
        """Test verifying a wrong password"""
        hashed = _hash_password("my_secret")
        assert _verify_password("wrong_password", hashed) is False

    def test_different_hashes_same_password(self):
        """Test that same password produces different hashes (salt)"""
        hash1 = _hash_password("same_password")
        hash2 = _hash_password("same_password")
        assert hash1 != hash2  # Different salts


# ==================== Authentication Tests ====================

class TestAuthentication:
    """Test authentication functionality"""

    def test_login_success(self, client):
        """Test successful login"""
        response = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client):
        """Test login with wrong password"""
        response = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        response = client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "password123"
        })
        assert response.status_code == 401

    def test_login_empty_credentials(self, client):
        """Test login with empty credentials"""
        response = client.post("/api/v1/auth/login", json={
            "username": "",
            "password": ""
        })
        assert response.status_code == 401


# ==================== Protected Endpoints Tests ====================

class TestProtectedEndpoints:
    """Test that endpoints require authentication"""

    def test_status_without_auth(self, client):
        """Test status endpoint without auth"""
        response = client.get("/api/v1/status")
        assert response.status_code in [401, 403]

    def test_status_with_auth(self, client, admin_token):
        """Test status endpoint with valid auth"""
        if admin_token is None:
            pytest.skip("Could not obtain admin token")
        response = client.get(
            "/api/v1/status",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_rules_without_auth(self, client):
        """Test rules endpoint without auth"""
        response = client.get("/api/v1/rules")
        assert response.status_code in [401, 403]

    def test_rules_with_auth(self, client, admin_token):
        """Test rules endpoint with valid auth"""
        if admin_token is None:
            pytest.skip("Could not obtain admin token")
        response = client.get(
            "/api/v1/rules",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200


# ==================== Admin Role Tests ====================

class TestAdminRole:
    """Test admin role requirements"""

    def test_create_rule_as_admin(self, client, admin_token):
        """Test creating a rule as admin"""
        if admin_token is None:
            pytest.skip("Could not obtain admin token")
        response = client.post(
            "/api/v1/rules",
            json={
                "src_ip": "10.0.0.0/8",
                "dst_port": 22,
                "protocol": "TCP",
                "action": "BLOCK",
                "priority": 10
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 201

    def test_create_rule_as_operator(self, client, operator_token):
        """Test creating a rule as operator (should fail)"""
        if operator_token is None:
            pytest.skip("Could not obtain operator token")
        response = client.post(
            "/api/v1/rules",
            json={
                "src_ip": "10.0.0.0/8",
                "dst_port": 22,
                "protocol": "TCP",
                "action": "BLOCK",
                "priority": 10
            },
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 403

    def test_block_ip_as_operator(self, client, operator_token):
        """Test blocking IP as operator (should fail - admin only)"""
        if operator_token is None:
            pytest.skip("Could not obtain operator token")
        response = client.post(
            "/api/v1/block/10.0.0.1",
            headers={"Authorization": f"Bearer {operator_token}"}
        )
        assert response.status_code == 403


# ==================== Health Endpoints Tests ====================

class TestHealthEndpoints:
    """Test health check endpoints (no auth required)"""

    def test_basic_health(self, client):
        """Test basic health endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_liveness_probe(self, client):
        """Test liveness probe"""
        response = client.get("/api/v1/health/liveness")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    def test_readiness_probe(self, client):
        """Test readiness probe"""
        response = client.get("/api/v1/health/readiness")
        # May return 200 or 503 depending on initialization
        assert response.status_code in [200, 503]


# ==================== CORS Tests ====================

class TestCORS:
    """Test CORS configuration"""

    def test_cors_restricted_origin(self, client):
        """Test that CORS is not open to all origins"""
        response = client.options(
            "/api/v1/status",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "GET"
            }
        )
        # Should NOT include the evil origin in Allow-Origin
        allow_origin = response.headers.get("access-control-allow-origin", "")
        assert allow_origin != "*"
        assert "evil.example.com" not in allow_origin


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
