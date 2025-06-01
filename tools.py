import json
import os
from dotenv import load_dotenv
from tavily import TavilyClient

load_dotenv()

tavily_client = TavilyClient(
    api_key=os.getenv('TAVILY_API_KEY')
)

# ---------
# functions
# ---------
def tavily_search(query) -> str:
    search_result = tavily_client.search(query, max_results=5, topic="general",
                                         search_depth="advanced", max_tokens=5000)
    return search_result

# --------------
# Dictionary map
# --------------

available_functions = {
    "tavily_search": tavily_search,
}

# -------------------
# Function Definitions
# -------------------

tools = [{

     "type": "function",
     "function": {
        "name": "tavily_search",
        "description": "search the web based on the user's query.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"}
            },

            "required": ["query"],
            "additionalProperties": False
        },

     },

}]












