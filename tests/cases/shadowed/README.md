Actions are removed if they're matched by a wildcard. That is, if you have:

- something:Action1
- something:Action2
- something:Action3
- something:Action*

then those will be replaced by a single

- something:Action*

action.
