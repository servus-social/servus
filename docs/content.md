## Nostr events

**NIP-01** (*kind 1*) events will become *notes*.
**NIP-23** (*kind 30023*) events ("long-form content") are used both as *posts* and as *pages*. The difference is that *pages* must have a `t` tag set to `page`.
**NIP-68** (*kind 20*) events will become *pictures*.
**NIP-99** (*kind 30402*) events will become *listings*.

**NIP-09** (*kind 5*) events are used to delete content.

Any other events will be saved under *events*.

## Directory structure

A "site" is identified by the domain name, which is passed by the browser using the [`Host` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/host).

```
.
├── themes
│   ├── hyde
│   ├── ...
│   └── ...
└── sites
    ├── domain1.com
    ├── domain2.com
    └── domain3.com
```

Each of these "sites" has the following structure:

```
├── _config.toml
├── _content
│   ├── notes
│   │   ├── <event_id>.md
│   │   └── [...]
│   ├── pages
│   │   ├── page1.md
│   │   └── [...]
|   └── posts
│       ├── post1.md
│       └── [...]
└── [...]
```

Files and directories starting with "." are ignored.

Files and directories starting with "_" have special meaning: `_config.toml`, `_content`.

Anything else will be directly served to the clients requesting it.
