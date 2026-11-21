

# ==========================================
# PHISHING EMAIL DETECTION SYSTEM
# LaunchED Cybersecurity Capstone Project
# ==========================================

import re

# Display project heading
print("=" * 45)
print("       PHISHING EMAIL DETECTION SYSTEM")
print("=" * 45)

# Collect email from user
print("\nPaste your email message below.")
print("Type END on a new line when finished.")

email_lines = []

while True:
    line = input()

    if line.strip().upper() == "END":
        break

    email_lines.append(line)

# Combine all email lines
email = "\n".join(email_lines)

# Convert email to lowercase
email_lower = email.lower()

# Define suspicious keywords
suspicious_keywords = [
    "winner",
    "congratulations",
    "claim now",
    "free prize",
    "urgent",
    "immediately",
    "account blocked",
    "verify your account",
    "password",
    "bank details",
    "click here"
]

# Detect suspicious keywords
detected_words = []

for word in suspicious_keywords:
    if word in email_lower:
        detected_words.append(word)

# Detect URLs
urls = re.findall(
    r'https?://[^\s]+|www\.[^\s]+',
    email_lower
)

# Identify suspicious URLs
suspicious_urls = []

for url in urls:

    url = url.rstrip(".,!?;:)")

    if (
        "bit.ly" in url
        or "tinyurl.com" in url
        or "t.co" in url
        or url.startswith("http://")
        or re.search(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}',
            url
        )
    ):
        suspicious_urls.append(url)

# Calculate risk score
risk_score = (
    len(detected_words) * 10
    + len(suspicious_urls) * 25
)

# Limit risk score to 100
risk_score = min(risk_score, 100)

# Display analysis results
print("\n" + "=" * 15 + " ANALYSIS RESULT " + "=" * 15)

print("\nSuspicious words detected:", detected_words)

print("URLs found:", urls)

print("Suspicious URLs:", suspicious_urls)

print("Risk Score:", risk_score, "/100")

# Classify email
if risk_score >= 45:
    print("\nResult: HIGH RISK - Possible Phishing Email")

elif risk_score >= 15:
    print("\nResult: MEDIUM RISK - Suspicious Email")

else:
    print("\nResult: LOW RISK - No suspicious indicators detected")

print("\n" + "=" * 15 + " ANALYSIS COMPLETED " + "=" * 15)
