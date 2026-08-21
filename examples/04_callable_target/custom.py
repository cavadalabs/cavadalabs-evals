async def async_target(request):
    return {
        "output": "READY" if request["input"] == "Reply with READY." else "UNKNOWN",
        "metadata": {"fixture": "async-local"},
    }
