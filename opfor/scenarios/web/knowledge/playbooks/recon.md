# Playbook: web recon

1. Get each seed path. Note the status, the server header, and any hints in the
   body.
2. Follow newly discovered same-host links, they widen the map of the app.
3. A 200 with a login form, an admin path, or a debug page is worth a closer
   look. A 401 or 403 marks a control that is present, judge whether it can be
   reached another way.
4. Stay within the campaign scope and the permitted action tier. Stop when the
   reachable surface is mapped and nothing new is appearing.
