import logging
import uuid
from pythonjsonlogger import jsonlogger
from fastmcp.client.logging import LogMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StreamableHttpConnection
from langgraph.prebuilt import create_react_agent
from langchain_aws import ChatBedrockConverse


# --- 1. Structured Logging Setup ---

# This formatter creates JSON logs with the fields defined in our schema.
# We add a custom formatter to handle the 'extra' dictionary.
class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        # Rename standard fields for consistency
        log_record['timestamp'] = log_record.pop('asctime')
        log_record['log_level'] = log_record.pop('levelname')
        # Ensure all 'extra' fields are at the top level
        if 'extra' in log_record:
            for key, value in log_record['extra'].items():
                log_record[key] = value
            del log_record['extra']

def get_structured_logger(name, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        # Use our custom formatter
        formatter = CustomJsonFormatter('%(asctime)s %(levelname)s %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    return logger

MCP_SERVER_NAME = "phishing_triage_mcp"
AGENT_ID = "phishing-triage-agent-01"
AGENT_NAME = "PhishingTriageAssistant"

# Get loggers for the agent's own actions and for the MCP tool logs
agent_logger = get_structured_logger(__name__)
mcp_logger = get_structured_logger(MCP_SERVER_NAME)

LOGGING_LEVEL_MAP = logging.getLevelNamesMapping()

async def log_handler(message: LogMessage, correlation_id: str, user_id: str):
    # Map the logging level string from MCP to the Python enum
    level = LOGGING_LEVEL_MAP[message.level.upper()]
    # Populate the structured log schema using 'extra'
    extra_context = {
        "agent_id": AGENT_ID,
        "agent_name": AGENT_NAME,
        "principal_user_id": user_id,
        "event_correlation_id": correlation_id,
        "source_mcp_server": MCP_SERVER_NAME
    }
    mcp_logger.log(level, message.data, extra=extra_context)

# --- 2. MCP Client and Agent Setup ---

async def run_phishing_triage(email_content: str, user_id: str):
    # Generate a unique ID for this entire task
    correlation_id = str(uuid.uuid4())
    
    # Log the start of the agent task
    agent_logger.info(
        "Starting phishing triage task.",
        extra={
            "agent_id": AGENT_ID,
            "agent_name": AGENT_NAME,
            "principal_user_id": user_id,
            "event_correlation_id": correlation_id,
            "event_action": "start_triage_task"
        }
    )

    # Connect to the MCP server over streamable-http
    client = MultiServerMCPClient()
    client.connections = {
        MCP_SERVER_NAME: StreamableHttpConnection(
            transport="streamable_http",
            url="http://localhost:8000/mcp",
            session_kwargs={
                # Set the logging callback to handle client-side logs
                "logging_callback": lambda msg: log_handler(msg, correlation_id, user_id)
            }
        )
    }

    # Replace with your model of choice
    model = ChatBedrockConverse(
        model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
        region_name="us-east-1",
        temperature=0.0,
        max_tokens=None,
    )
    tools = await client.get_tools()

    agent_prompt = """
    You are a Tier 1 SOC Analyst AI Assistant. Your job is to analyze the user-reported email
    and determine if it is malicious, suspicious, or benign.
    1. First, extract all indicators of compromise (IOCs) from the email.
    2. For each IOC, use your tools to check its reputation.
    3. Based on the reputation of the IOCs, provide a final verdict and a summary of your findings.
    """
    
    react_agent = create_react_agent(model, tools, prompt=agent_prompt)

    # --- 3. Invoke Agent and Log Results ---
    
    response = await react_agent.ainvoke(
        {"messages": [{"role": "user", "content": email_content}]}
    )
    
    final_verdict = response['messages'][-1].content
    
    agent_logger.info(
        "Completed phishing triage task.",
        extra={
            "agent_id": AGENT_ID,
            "agent_name": AGENT_NAME,
            "principal_user_id": user_id,
            "event_correlation_id": correlation_id,
            "event_action": "complete_triage_task",
            "threat_verdict": final_verdict # Capturing the agent's final conclusion
        }
    )
    return final_verdict

if __name__ == "__main__":
    import asyncio

    suspicious_email = """
    From: security@yourbank-logins.com
    Subject: Urgent: Suspicious Account Activity

    We have detected unusual activity on your account. Please verify your identity immediately
    by clicking here: http://evil-phish.com/login

    Also, please review the attached report of your activity.
    File hash: e88482b4026343e36bf48c1579a3f033
    """
    
    result = asyncio.run(run_phishing_triage(suspicious_email, user_id="soc_analyst_jane_doe"))
    print("\n--- Agent Final Verdict ---")
    print(result)