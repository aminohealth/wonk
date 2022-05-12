This is more complex than other case and exercizes `minify`'s repeated combination passes:

- First it combines sets 1 + 2 => A, 3 + 4 => B, 5 + 6 => C, and 7 + 8 => D, because they have similar resources but different actions.

- Next it combines A + B => A', and C + D => C', because they have similar actions but different resources.

- Finally, it combines A' + C', which have the same resources but different actions, into a final statement that covers all actions and resources.
