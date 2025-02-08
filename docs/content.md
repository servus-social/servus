## Directory structure

You can run the **Servus** executable from any directory. On start, it looks for a directory named `themes` and a directory named `sites` and loads all available themes and sites that it finds.

Themes are expected to be **Zola** themes.

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
