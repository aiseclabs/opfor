# Mock scenario

A tiny offline world used to exercise the engine without a network. The agent
should read the index page first, notice that doing so captures a credential,
then poke the admin entrypoint that the credential unlocks. Stop once the admin
page has been read and its loot recorded.
