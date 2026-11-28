"""Container and edge hardening (PR 15). Reads the Dockerfile, docker-compose.yml, .dockerignore and the nginx
config, and fails on what the OWASP Docker Security Cheat Sheet rules out. Needs PyYAML (installed in CI)."""
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
NETWORKS = COMPOSE["networks"]
DOCKERFILE = (ROOT / "Dockerfile").read_text()
NGINX_CONF = (ROOT / "nginx" / "default.conf").read_text()
NGINX_MAIN = (ROOT / "nginx" / "nginx.conf").read_text()
# The services that hold data or run code: none of them may be reachable from, or reach, outside the cluster.
INTERNAL_ONLY = ("db", "migrate", "soc-core", "worker")
APP_SERVICES = ("soc-core", "worker", "migrate")


def _as_list(value):
    return value if isinstance(value, list) else [value] if value else []


def test_no_latest_tags_and_every_base_image_is_pinned_to_a_patch_version():
    for name, svc in SERVICES.items():
        image = svc.get("image")
        if image is None:
            continue
        assert "latest" not in image, f"{name} uses a floating tag: {image}"
    assert re.fullmatch(r"postgres:16\.\d+", SERVICES["db"]["image"]), SERVICES["db"]["image"]
    assert re.fullmatch(r"nginx:\d+\.\d+\.\d+-alpine", SERVICES["nginx"]["image"]), SERVICES["nginx"]["image"]
    froms = re.findall(r"^FROM\s+(\S+)", DOCKERFILE, flags=re.MULTILINE)
    assert froms and all(re.fullmatch(r"python:3\.12\.\d+-slim", f) for f in froms), froms
    assert ":latest" not in DOCKERFILE and ":latest" not in (ROOT / "docker-compose.yml").read_text()


def test_nothing_is_privileged_and_the_docker_socket_is_never_mounted():
    for name, svc in SERVICES.items():
        assert svc.get("privileged") is not True, f"{name} is privileged"
    for path in [ROOT / "docker-compose.yml", ROOT / "Dockerfile", *(ROOT / "nginx").iterdir()]:
        if path.is_file():
            assert "docker.sock" not in path.read_text(), f"{path.name} mentions the Docker socket"


def test_the_app_image_runs_as_a_non_root_numeric_user():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, flags=re.MULTILINE)
    assert users, "the Dockerfile must set USER"
    last = users[-1]
    assert last.isdigit() and int(last) != 0 and last != "root", f"runs as {last}"


def test_the_database_is_only_on_an_internal_network_and_publishes_no_port():
    assert SERVICES["db"]["networks"] == ["soc_internal"]
    assert NETWORKS["soc_internal"].get("internal") is True
    assert "ports" not in SERVICES["db"]


def test_internal_services_have_no_route_outside_the_cluster():
    for name in INTERNAL_ONLY:
        networks = SERVICES[name]["networks"]
        assert networks, f"{name} has no network"
        for net in networks:
            assert NETWORKS[net].get("internal") is True, f"{name} is on {net}, which has an external route"
        assert "ports" not in SERVICES[name], f"{name} publishes a port"


def test_only_the_tls_edge_is_published_and_only_on_https_and_http():
    published = {name: svc["ports"] for name, svc in SERVICES.items() if "ports" in svc}
    assert set(published) == {"nginx"}, published
    assert published["nginx"] == ["443:8443", "80:8080"]
    assert "soc_edge" in SERVICES["nginx"]["networks"]


def test_app_services_are_read_only_with_no_capabilities_and_no_new_privileges():
    for name in APP_SERVICES + ("nginx",):
        svc = SERVICES[name]
        assert svc.get("read_only") is True, f"{name} must have read_only: true"
        assert "/tmp" in [t.split(":")[0] for t in _as_list(svc.get("tmpfs"))], f"{name} needs a /tmp tmpfs"
        assert "ALL" in svc.get("cap_drop", []), f"{name} must drop ALL capabilities"
        assert "no-new-privileges:true" in svc.get("security_opt", []), f"{name} must set no-new-privileges"


def test_the_database_keeps_no_new_privileges():
    assert "no-new-privileges:true" in SERVICES["db"]["security_opt"]


def test_the_build_context_cannot_carry_secrets_into_an_image():
    ignored = (ROOT / ".dockerignore").read_text().splitlines()
    assert ".env" in ignored and "nginx/tls" in ignored
    assert any(line.strip() == "**/*.key" for line in ignored)


def test_the_edge_serves_tls_only_with_the_required_security_headers_and_body_limit():
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in NGINX_CONF
    assert not re.search(r"ssl_protocols[^;]*TLSv1(\s|;)", NGINX_CONF.replace("TLSv1.2", "").replace("TLSv1.3", ""))
    for header in ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
                   "Content-Security-Policy", "Referrer-Policy"):
        assert f'add_header {header} ' in NGINX_CONF, f"missing {header}"
    assert "client_max_body_size 1m;" in NGINX_CONF
    assert "server_tokens off;" in NGINX_MAIN
    assert "proxy_pass http://soc-core:5000;" in NGINX_CONF
    assert "return 301 https://" in NGINX_CONF
