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

## Unsigned content

If you want to use Servus in the same way you would use a traditional SSG, by editing markdown files directly, without using a Nostr client to post, you can still do that. The only thing you need in that case is a **Nostr private key** that you pass using an environment variable in addition to the `--sign-content` flag.

Basically you would start Servus like this:

`$ SERVUS_SECRET_KEY=5f263b4561008922b7efbcbcc9066072246e0b4094f92a016691dfe4c0eba358 ./servus --sign-content`

What happens if you do this is the following... when Servus tries to parse a Nostr event from a `.md` file and it fails due to the event being incomplete (missing ID, signature, etc) it generates a fresh event on the fly and signs it with the provided *secret key*. That new event is only held in memory and served to Nostr and HTTP clients. If you want to edit it, you should edit the original `.md` file and restart Servus. Servus will not write anything back to the `.md` file.

Files that look like `yyyy-mm-dd-slug.md` will become posts and files that look like `slug.md` will become pages.

Note: this `SERVUS_SECRET_KEY` key is different from the `pubkey` present in the `_config.toml` file! In fact the two are mutually exclusive. That is, if you decided to pass `--sign-content` and a secret key, your sites **cannot** also have a pubkey. This essentially means that content managed in this way cannot be edited from Nostr clients and you have to do it by manually editing `.md` files!