import re
from fastmcp import FastMCP, Context

# In a real application, these would be calls to external threat intelligence APIs
# (e.g., VirusTotal, AbuseIPDB, etc.). We mock them here for demonstration.
def mock_threat_intel_api_url(url: str) -> dict:
    if "evil-phish.com" in url:
        return {"verdict": "malicious", "threat_type": "phishing"}
    return {"verdict": "benign", "threat_type": None}

def mock_threat_intel_api_hash(file_hash: str) -> dict:
    if file_hash.startswith("e88482"):
        return {"verdict": "malicious", "threat_type": "malware"}
    return {"verdict": "benign", "threat_type": None}


mcp = FastMCP("PhishingTriage")

@mcp.tool
async def extract_iocs_from_email(email_body: str, ctx: Context) -> dict:
    """
    Extracts Indicators of Compromise (IOCs) such as URLs, domains, IP addresses,
    and file hashes from the body of an email.
    """
    await ctx.info("Starting IOC extraction from email body.")
    
    # Simple regex for demonstration purposes. Production use requires more robust parsing.
    urls = re.findall(r'https?://\S+', email_body)
    hashes_md5 = re.findall(r'\b[a-fA-F0-9]{32}\b', email_body)
    
    iocs = {"urls": urls, "hashes_md5": hashes_md5}
    await ctx.info(f"Extracted IOCs: {iocs}")
    
    return {"success": True, "iocs": iocs}

@mcp.tool
async def get_url_reputation(url: str, ctx: Context) -> dict:
    """
    Checks the reputation of a given URL against a threat intelligence source.
    """
    await ctx.info(f"Querying threat intelligence for URL: {url}")
    try:
        result = mock_threat_intel_api_url(url)
        await ctx.info(
            f"Reputation for {url} is '{result['verdict']}'"
            f"with threat type '{result['threat_type']}'."
        )
        return {"success": True, "url": url, **result}
    except Exception as e:
        await ctx.error(f"Failed to get URL reputation for {url}: {str(e)}")
        raise

@mcp.tool
async def get_file_hash_reputation(file_hash: str, ctx:Context) -> dict:
    """
    Checks the reputation of a given MD5 file hash against a threat intelligence source.
    """
    await ctx.info(f"Querying threat intelligence for file hash: {file_hash}")
    try:
        result = mock_threat_intel_api_hash(file_hash)
        await ctx.info(
            f"Reputation for {file_hash} is '{result['verdict']}'"
            f"with threat type '{result['threat_type']}'."
        )
        return {"success": True, "file_hash": file_hash, **result}
    except Exception as e:
        await ctx.error(f"Failed to get file hash reputation for {file_hash}: {str(e)}")
        raise

if __name__ == "__main__":
    """
    In a production environment, this server should be secured with TLS encryption
    and deployed within a private network (e.g., a VPC) to ensure access
    is restricted to trusted applications and agents. We use streamable-http
    instead of stdio to simulate a realistic microservice architecture where 
    multiple agents consume these tools over a network.
    """
    mcp.run(transport="streamable-http")
