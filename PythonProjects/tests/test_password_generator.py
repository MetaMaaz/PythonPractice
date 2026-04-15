import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import string
import math
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from PasswordGenerator import (
    generate_password, get_strength, check_hibp,
    copy_to_clipboard, get_int_input, calculate_entropy,
    time_to_crack, validate_hibp_url,
)


class TestGeneratePassword(unittest.TestCase):

    def test_correct_length(self):
        password = generate_password(5, 2, 3)
        self.assertEqual(len(password), 10)

    def test_empty_password(self):
        password = generate_password(0, 0, 0)
        self.assertEqual(password, "")

    def test_only_letters(self):
        password = generate_password(8, 0, 0)
        self.assertEqual(len(password), 8)

    def test_exclude_ambiguous(self):
        password = generate_password(20, 0, 10, exclude_ambiguous=True)
        ambiguous = os.getenv("AMBIGUOUS_CHARS", "0OolI1")
        for char in ambiguous:
            self.assertNotIn(char, password)

    def test_uses_cryptographic_randomness(self):
        # Verify passwords aren't identical across calls (would indicate broken RNG)
        passwords = {generate_password(10, 2, 2) for _ in range(10)}
        self.assertGreater(len(passwords), 1)


class TestGetStrength(unittest.TestCase):

    def test_strong(self):
        self.assertEqual(get_strength(8, 2, 2), "Strong")

    def test_medium(self):
        self.assertEqual(get_strength(6, 1, 1), "Medium")

    def test_weak(self):
        self.assertEqual(get_strength(3, 0, 0), "Weak")


class TestValidateHibpUrl(unittest.TestCase):

    def test_valid_url(self):
        self.assertTrue(validate_hibp_url("https://api.pwnedpasswords.com/range/ABCDE"))

    def test_http_rejected(self):
        self.assertFalse(validate_hibp_url("http://api.pwnedpasswords.com/range/ABCDE"))

    def test_wrong_domain_rejected(self):
        self.assertFalse(validate_hibp_url("https://evil.com/range/ABCDE"))

    def test_no_scheme_rejected(self):
        self.assertFalse(validate_hibp_url("api.pwnedpasswords.com/range/ABCDE"))


class TestCheckHIBP(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_password_found_in_breach(self, mock_urlopen):
        sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"  # SHA1 of "password"
        suffix = sha1[5:]
        mock_response = MagicMock()
        mock_response.read.return_value = f"{suffix}:1234\nABCDE:5".encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check_hibp("password")
        self.assertEqual(result, 1234)

    @patch("urllib.request.urlopen")
    def test_password_not_in_breach(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"AAAAA:10\nBBBBB:5"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check_hibp("uniquepassword123!")
        self.assertEqual(result, 0)

    @patch("urllib.request.urlopen", side_effect=Exception("Network error"))
    def test_api_unreachable(self, mock_urlopen):
        result = check_hibp("anypassword")
        self.assertIsNone(result)

    @patch.dict(os.environ, {"HIBP_URL": "http://evil.com/range"})
    def test_rejects_http_url(self):
        result = check_hibp("testpassword")
        self.assertIsNone(result)

    @patch.dict(os.environ, {"HIBP_URL": "https://evil.com/range"})
    def test_rejects_wrong_domain(self):
        self.assertFalse(validate_hibp_url("https://evil.com/range/ABCDE"))
        result = check_hibp("testpassword")
        self.assertIsNone(result)


class TestCopyToClipboard(unittest.TestCase):

    @patch("PasswordGenerator.clear_clipboard_after")
    @patch("subprocess.run")
    @patch("platform.system", return_value="Darwin")
    def test_macos_clipboard(self, mock_platform, mock_run, mock_clear):
        copy_to_clipboard("testpassword")
        mock_run.assert_called_once_with("pbcopy", input=b"testpassword", check=True)
        mock_clear.assert_called_once()

    @patch("PasswordGenerator.clear_clipboard_after")
    @patch("subprocess.run")
    @patch("platform.system", return_value="Windows")
    def test_windows_clipboard(self, mock_platform, mock_run, mock_clear):
        copy_to_clipboard("testpassword")
        mock_run.assert_called_once_with("clip", input=b"testpassword", check=True)

    @patch("PasswordGenerator.clear_clipboard_after")
    @patch("subprocess.run")
    @patch("platform.system", return_value="Linux")
    def test_linux_clipboard_no_shell_true(self, mock_platform, mock_run, mock_clear):
        copy_to_clipboard("testpassword")
        # Verify shell=True is NOT used (command injection fix)
        mock_run.assert_called_once_with(
            ["xclip", "-selection", "clipboard"],
            input=b"testpassword", check=True,
        )

    @patch("platform.system", return_value="UnknownOS")
    def test_unsupported_os(self, mock_platform):
        try:
            copy_to_clipboard("testpassword")
        except Exception:
            self.fail("copy_to_clipboard raised an exception on unsupported OS")


class TestGetIntInput(unittest.TestCase):

    @patch("builtins.input", return_value="5")
    def test_valid_input(self, mock_input):
        result = get_int_input("Enter a number:")
        self.assertEqual(result, 5)

    @patch("builtins.input", side_effect=["abc", "-1", "3"])
    def test_retries_on_bad_input(self, mock_input):
        result = get_int_input("Enter a number:")
        self.assertEqual(result, 3)
        self.assertEqual(mock_input.call_count, 3)

    @patch("builtins.input", return_value="0")
    def test_zero_is_valid(self, mock_input):
        result = get_int_input("Enter a number:")
        self.assertEqual(result, 0)


class TestCalculateEntropy(unittest.TestCase):

    def test_letters_only(self):
        entropy = calculate_entropy(10, 10, 0, 0)
        expected = 10 * math.log2(52)
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_all_character_types(self):
        entropy = calculate_entropy(12, 6, 3, 3)
        pool_size = len(string.ascii_letters) + len(string.punctuation) + len(string.digits)
        expected = 12 * math.log2(pool_size)
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_zero_length(self):
        entropy = calculate_entropy(0, 0, 0, 0)
        self.assertEqual(entropy, 0.0)

    def test_exclude_ambiguous_reduces_entropy(self):
        normal = calculate_entropy(10, 10, 0, 0, exclude_ambiguous=False)
        reduced = calculate_entropy(10, 10, 0, 0, exclude_ambiguous=True)
        self.assertGreater(normal, reduced)


class TestTimeToCrack(unittest.TestCase):

    def test_low_entropy(self):
        result = time_to_crack(10)
        self.assertIn("seconds", result)

    def test_high_entropy(self):
        result = time_to_crack(80)
        self.assertIn("years", result)

    def test_zero_entropy(self):
        result = time_to_crack(0)
        self.assertIn("seconds", result)

    def test_minutes_range(self):
        # ~36 bits → ~68 seconds at 1B guesses/sec
        result = time_to_crack(36)
        self.assertIn("minutes", result)


class TestRateLimitAndTimeout(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_timeout_is_passed_to_urlopen(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"AAAAA:10"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        check_hibp("testpassword")
        call_kwargs = mock_urlopen.call_args
        self.assertEqual(call_kwargs[1]["timeout"], 5)

    @patch("urllib.request.urlopen", side_effect=TimeoutError("Connection timed out"))
    def test_timeout_returns_none(self, mock_urlopen):
        result = check_hibp("testpassword")
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_rate_limit_enforced(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"AAAAA:10"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        import PasswordGenerator
        PasswordGenerator._last_hibp_call = time.time()
        start = time.time()
        check_hibp("testpassword")
        elapsed = time.time() - start
        self.assertGreaterEqual(elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()
