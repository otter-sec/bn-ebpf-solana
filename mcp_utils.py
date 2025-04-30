import json

def flatten(res) -> str:
    if isinstance(res, list):
        parts = []
        for x in res:
            if hasattr(x, "text"):
                parts.append(x.text)
            else:
                parts.append(str(x))
        return "\n".join(parts)
    if hasattr(res, "text"):
        return res.text
    return str(res)

#anthropic uses snake_case
def mcp_to_anthropic(tool):
    return {
        "name":         tool.name,
        "description":  tool.description,
        "input_schema": tool.inputSchema,
    }

def blocks_to_str(blocks) -> str:
    out = []
    for block in blocks:
        if block.type == "text":
            out.append(block.text)
        elif block.type == "tool_use":
            #display tool call for the llm
            out.append(f"[tool_use {block.name} → {json.dumps(block.input)}]")
        elif block.type == "tool_result":
            out.append(f"[tool_result for {block.tool_use_id}: {block.content}]")
    return "".join(out)


