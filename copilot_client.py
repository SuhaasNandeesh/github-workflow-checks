import os
import json
import subprocess
import urllib.request
import urllib.error
import ssl


class CopilotClient:
    def __init__(self, model_name=None):
        # Default to standard model if none provided
        self.model_name = model_name or "gpt-4o"
        self.token = self._retrieve_token()

    def _retrieve_token(self):
        """Retrieves GitHub/Copilot token from environment, configuration files, or the GitHub CLI."""
        # 1. Check environment variables
        token = os.environ.get("COPILOT_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            return token

        # 2. Check VS Code / Copilot local apps.json
        home = os.path.expanduser("~")
        apps_paths = [
            os.path.join(home, ".config", "github-copilot", "apps.json"),
            os.path.join(home, "AppData", "Local", "github-copilot", "apps.json")  # Windows fallback
        ]
        
        for path in apps_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        oauth = data.get("oauth_token") or data.get("github.com", {}).get("oauth_token")
                        if oauth:
                            return oauth
                except Exception:
                    pass

        # 3. Check hosts.json
        hosts_paths = [
            os.path.join(home, ".config", "github-copilot", "hosts.json"),
            os.path.join(home, "AppData", "Local", "github-copilot", "hosts.json")
        ]
        for path in hosts_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        oauth = data.get("github.com", {}).get("oauth_token") or data.get("oauth_token")
                        if oauth:
                            return oauth
                except Exception:
                    pass

        # 4. Try running GitHub CLI 'gh auth token'
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            cli_token = result.stdout.strip()
            if cli_token:
                return cli_token
        except Exception:
            pass

        raise ValueError(
            "Could not retrieve GitHub/Copilot credentials.\n"
            "Please login to GitHub CLI ('gh auth login') or authenticate via VS Code Copilot extension."
        )

    def request_completion(self, system_prompt, user_prompt):
        """Sends chat request to GitHub Copilot completions endpoint and returns text content."""
        url = "https://api.githubcopilot.com/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Copilot-Integration-Id": "vscode-chat"
        }
        
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1
        }
        
        data_bytes = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        # Configure standard verified SSL context
        try:
            context = ssl.create_default_context()
        except Exception:
            context = None

        try:
            with urllib.request.urlopen(req, timeout=30, context=context) as response:
                if response.status == 200:
                    resp_data = json.loads(response.read().decode('utf-8'))
                    choices = resp_data.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")
                        return content
                    raise ValueError("Empty response choices received from Copilot API.")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8') if e.fp else ""
            raise ValueError(f"Copilot API error ({e.code}): {e.reason}\nBody: {err_body}")
        except Exception as e:
            # Fallback for SSL certificate verification errors on macOS
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                print("Warning: SSL certificate verification failed. Retrying with unverified context...")
                try:
                    unverified_context = ssl._create_unverified_context()
                    with urllib.request.urlopen(req, timeout=30, context=unverified_context) as response:
                        if response.status == 200:
                            resp_data = json.loads(response.read().decode('utf-8'))
                            choices = resp_data.get("choices", [])
                            if choices:
                                return choices[0].get("message", {}).get("content", "")
                except Exception as retry_err:
                    raise ValueError(f"Failed to communicate with Copilot API even with unverified SSL: {str(retry_err)}")
            raise ValueError(f"Failed to communicate with Copilot API: {str(e)}")
