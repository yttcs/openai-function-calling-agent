### An OpenAI function calling agent (as opposed to a ReAct agent) using the following: 

1. Backend: FastAPI/SQL Model.
2. Frontend: Jinja2, Bootstrap, and fetch().
3. Security: Oauth2 with password flow using JWT bearer tokens and a remote MariaDB user identity database hosted on a DigitalOcean VPS.


This is a work in progress and will have multiple updates on a weekly basis.
I'm trying to get as "old school"/legacy as possible, so I'm sticking with gpt-3.5-turbo and the completions API (no frameworks until it's absolutely necessary).

Todo list for this week:

1. Add some more tools
2. Do some error handling to address when the LLM decides to make a function call with the wrong arguments.
3. Get all the code out of main.py and organise it.
4. Deploy to AWS lambda using Podman instead of a Zip file.



