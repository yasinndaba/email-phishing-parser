from analyzer.html_analysis import analyze_html


def test_html_email_detection():
    html = """
    <html>
        <body>
            <h1>Security Alert</h1>
            <p>Please verify your account.</p>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["is_html"] is True
    assert result["score"] >= 0


def test_html_link_extraction():
    html = """
    <html>
        <body>
            <a href="https://example.com/login">
                Login
            </a>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["link_count"] == 1
    assert result["links"][0]["href"] == (
        "https://example.com/login"
    )
    assert result["links"][0]["hostname"] == "example.com"


def test_suspicious_html_url():
    html = """
    <html>
        <body>
            <a href="https://evil.example/verify/account">
                Verify Account
            </a>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["score"] > 0

    assert any(
        "suspicious keywords" in finding.lower()
        for finding in result["findings"]
    )


def test_html_link_text_mismatch():
    html = """
    <html>
        <body>
            <a href="https://evil.example/login">
                https://microsoft.com/login
            </a>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["link_count"] == 1
    assert result["links"][0]["suspicious"] is True

    assert any(
        "mismatch" in finding.lower()
        for finding in result["findings"]
    )


def test_html_ip_link():
    html = """
    <html>
        <body>
            <a href="http://192.0.2.10/login">
                Login
            </a>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["score"] > 0

    assert any(
        "ip address" in finding.lower()
        for finding in result["findings"]
    )


def test_html_form_detection():
    html = """
    <html>
        <body>
            <form action="https://evil.example/login">
                <input type="text">
                <input type="password">
            </form>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["forms"] == 1
    assert result["score"] > 0


def test_html_script_detection():
    html = """
    <html>
        <body>
            <script>
                alert("test");
            </script>
        </body>
    </html>
    """

    result = analyze_html(html)

    assert result["scripts"] == 1
    assert result["score"] > 0


def test_plain_text_email():
    body = """
    Hello,

    This is a normal plain-text email.
    """

    result = analyze_html(body)

    assert result["is_html"] is False
    assert result["link_count"] == 0
    assert result["forms"] == 0
    assert result["scripts"] == 0
    assert result["score"] == 0
    assert result["findings"] == []