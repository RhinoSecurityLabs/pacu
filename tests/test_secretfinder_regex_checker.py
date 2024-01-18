import pytest
from pacu.core.secretfinder.utils import regex_checker

# Test data
TEST_DATA = [
    ("This is just a normal string.", False, None),
    ("My AWS client ID is AKIA1234567890ABCDEF", True, "AWS_Client"),
    ("GitHub token: ghp_1234567890abcdef1234567890abcdef1234", True, "GitHub Personal Token"),
    ("GitHub token: ghs_1234567890abcdefghijklmnopqrstuvwxyzAB", True, "GitHub Actions Token"),
    ("GitHub token: github_pat_abcdefghijABCDEFGHIJ12_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567", True, "GitHub Fine-grained Token"),
    ("'GitHub': 'abcdefghijklmnopqrstuvwx1234567890123456'", True, "GitHub Generic"),
    ("This text contains an IP: 192.168.1.1", True, "IPv4"),
    ("Artifactory API key: AKCabcdefghijABCDEFGHIJ1234567890", True, "Artifactory_API"),
    ("Artifactory Password: AP1ABCDabcdefghijABCDEFGHIJ12", True, "Artifactory_Password"),
    ("Authorization: basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", True, "Basic_Auth"),
    ("Authorization: bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==", True, "Bearer_Auth"),
    ("AWS MWS Key: amzn.mws.4ea38b7b-6c4c-4d0f-a6f2-123456789012", True, "AWS_MWS"),
    ("Generic API Key: 'api_key' = 'abcdefghijklmnopqrstuvwxyz12345678901234567890ABCDEF\"", True, "Generic API Key"),
    ("Generic Secret: 'secret_key'= '_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890123456789@$%^&0abcdef\"", True, "Generic Secret"),
    ("Google API Key: AIzaSyC123456789012345678901234567890123", True, "Google API Key"),
    ("Google Cloud Platform API Key: AIzaSyC123456789012345678901234567890123", True, "Google Cloud Platform API Key"),
    ("Google Cloud Platform OAuth: 123456789012-abcd1234abcd1234abcd1234abcd1234.apps.googleusercontent.com", True, "Google Cloud Platform OAuth"),
    ("Google Drive API Key: AIzaSyC123456789012345678901234567890123", True, "Google Drive API Key"),
    ("Google Drive OAuth: 123456789012-abcd1234abcd1234abcd1234abcd1234.apps.googleusercontent.com", True, "Google Drive OAuth"),
    ("Google Service Account: \"type\": \"service_account\"", True, "Google (GCP) Service-account"),
    ("HEROKU API Key: hEroKu_1234567-ABC12345-AB12-CD34-12AB-123456789ABA", True, "HEROKU_API"),
    ("IPv4 address: 192.168.1.1", True, "IPv4"),
    ("MAILGUN API Key: key-abcdefghijklmnopqrstuvwxyz1234567890123456", True, "MAILGUN_API"),
    ("MD5 Hash: 5f4dcc3b5aa765d61d8327deb882cf99", True, "MD5"),
    ("Slack Token: xoxb-123456789012-ABCDEFGHIJKLMNOPQRSTUVWX", True, "SLACK_TOKEN"),
    ("Slack Webhook: https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwxyz123456", True, "SLACK_WEBHOOK"),
    ("RSA Private Key: -----BEGIN RSA PRIVATE KEY-----", True, "RSA private key"),
    ("DSA Private Key: -----BEGIN DSA PRIVATE KEY-----", True, "SSH (DSA) private key"),
    ("EC Private Key: -----BEGIN EC PRIVATE KEY-----", True, "SSH (EC) private key"),
    ("PGP Private Key: -----BEGIN PGP PRIVATE KEY BLOCK-----", True, "PGP private key block"),
    ("SSH (ed25519) private key: -----BEGIN OPENSSH PRIVATE KEY-----", True, "SSH (ed25519) private key"),
    ("Twilio API Key: SKAbCdEf123AbCdEf123AbCdEf123AbCdE", True, "Twilio API Key"),
    ("Twitter Access Token: twitter_1234567890123456789012345678901234567890-1234567890123456789012345678901234567890", True, "Twitter Access Token"),
]

@pytest.mark.parametrize("test_input,expected_result,expected_key", TEST_DATA)
def test_regex_checker(test_input, expected_result, expected_key):
    result = regex_checker(test_input)

    if expected_result:
        assert result
        assert expected_key in result
    else:
        assert not result

