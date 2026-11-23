One file per credential, read only by the `gateway` container (mounted read-only at /run/secrets).
Never mounted into the sandbox. Manage with `./re secret set|ls|rm`.

| file | used by route |
|---|---|
| anthropic_api_key | /anthropic |
| openai_api_key | /openai |
| deepseek_api_key | /deepseek |
| openrouter_api_key | /openrouter |
| venice_api_key | /venice |
