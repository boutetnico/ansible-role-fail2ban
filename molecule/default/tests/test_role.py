import pytest


@pytest.mark.parametrize(
    "name",
    [
        ("fail2ban"),
    ],
)
def test_dependencies_are_installed(host, name):
    package = host.package(name)
    assert package.is_installed


@pytest.mark.parametrize(
    "path,user,group,mode",
    [
        ("/etc/fail2ban/fail2ban.local", "root", "root", 0o644),
        ("/etc/fail2ban/jail.local", "root", "root", 0o644),
        ("/etc/fail2ban/filter.d/nginx-badbots.conf", "root", "root", 0o644),
        ("/etc/fail2ban/action.d/nginx-deny-host.conf", "root", "root", 0o644),
    ],
)
def test_config_files_exist(host, path, user, group, mode):
    config = host.file(path)
    assert config.exists
    assert config.is_file
    assert config.user == user
    assert config.group == group
    assert config.mode == mode


def test_fail2ban_local_contains_expected_settings(host):
    config = host.file("/etc/fail2ban/fail2ban.local")
    assert config.contains("loglevel = WARNING")


def test_jail_local_contains_expected_settings(host):
    config = host.file("/etc/fail2ban/jail.local")
    assert config.contains("ignoreip = 127.0.0.1/8")
    assert config.contains("nginx-badbots")


@pytest.mark.parametrize(
    "name",
    [
        ("fail2ban"),
    ],
)
def test_service_is_running_and_enabled(host, name):
    service = host.service(name)
    assert service.is_enabled
    assert service.is_running


def test_fail2ban_client_command_works(host):
    cmd = host.run("fail2ban-client --version")
    assert cmd.rc == 0


def test_action_multiline_values_are_indented(host):
    config = host.file("/etc/fail2ban/action.d/nginx-deny-host.conf")
    content = config.content_string
    for line in content.splitlines():
        # Lines that are continuations (not section headers, not key=value, not blank, not comments)
        if (
            line
            and not line.startswith("[")
            and "=" not in line
            and not line.startswith("#")
        ):
            assert line.startswith(" "), f"Continuation line is not indented: {line!r}"


def test_filter_multiline_values_are_indented(host):
    config = host.file("/etc/fail2ban/filter.d/nginx-badbots.conf")
    content = config.content_string
    for line in content.splitlines():
        if (
            line
            and not line.startswith("[")
            and "=" not in line
            and not line.startswith("#")
        ):
            assert line.startswith(" "), f"Continuation line is not indented: {line!r}"
