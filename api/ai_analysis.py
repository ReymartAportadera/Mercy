from openai import OpenAI

# NVIDIA NIM - Free API
client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key="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"  # Your actual key
)

def analyze_file_ai(entropy, patterns, imports, risk_score):
    try:
        prompt = f"""Analyze this file for malware:

Entropy: {entropy}
Suspicious Patterns: {patterns}
Risky Imports: {imports}
Risk Score: {risk_score}/100

Is this file malicious, suspicious, or safe?
Answer in 2-3 sentences."""

        response = client.chat.completions.create(
            model="meta/llama-3.1-70b-instruct",  # Free model
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity malware analyst."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.3
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"