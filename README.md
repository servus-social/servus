# Servus

![alt text](https://github.com/servuscms/servus.page/blob/master/images/logo.png?raw=true)

## About

**Servus** is a minimalist **social media server** fully self-contained within one executable file.

- [x] CMS
- [x] Personal Nostr relay
- [x] Personal file server (Blossom & NIP-96)

### CMS

As a CMS, Servus sits somewhere in between [Jekyll](https://jekyllrb.com/) and WordPress.

Like Jekyll:
 * all content is stored in flat files

Unlike Jekyll:
 * no build step
 * no need to manually edit the files
 * no need to configure a web server
 * no dependencies on Ruby Gems, Docker, etc.

Like WordPress:
 * easy administration

Unlike WordPress:
 * no need to have a database like MySQL
 * no need to run a web server like Apache

### Personal Nostr Relay & File server (Blossom & NIP-96)

 - [x] own your identity
 - [x] own your data

If you already have a Nostr keypair, you already own your identity. But you only really own your data when you self-host it. Don't rely on other relays to store your data.

[Blossom](https://github.com/hzrd149/blossom) and [NIP-96](https://github.com/nostr-protocol/nips/blob/master/96.md) are protocols adjacent to Nostr that specify how files (such as images) are to be stored on HTTP servers.

## Features

* **Single executable** that you can `scp` to a bare VPS and it will just work. Without Docker, without MySQL, without Python venv, without Node or PHP, without setting up an nginx reverse proxy and whatnot... You shouldn't need any of that to self-host your personal website!
* All content and settings stored as **plain text**. Except, of course, images or other media you have as content. Not in a SQL database, not in "the cloud", not in "some Nostr relays"... but in plain text files on the machine running Servus.
* As a corolary of the above, a *full backup* is just an `rsync` command... or a `.zip` file. Download a copy of it to your laptop, write a script that imports it to another CMS, search it, copy-paste parts of it to other places...
* All content served to the readers is **plain HTML served over HTTP(S)**. No Javascript that generates UI elements on the client side, no Javascript that queries Nostr relays or uses background HTTP requests to get content from the server. What you get is a plain "website" that you can open in any web browser or even using `wget`.
* **Support for "themes"**. *Simple* doesn't mean ugly nor does it mean it should be limited in any way. Avoiding unnecessary client-side technologies doesn't mean the websites built using Servus need to look "old school" or be limited in functionality. In fact, themes *can* use Javascript *if they want to* - for certain effects, etc. The goal is to not *require* Javascript as part of the overall architecture, not to avoid it at any cost.
* **Multiple websites** that can be separately administered in one instance. So you will be able to, for example, self-host your personal website, your business's website and have your uncle host his blog, all with a single Servus instance.

## Performance and limitations

The web is the social network!

**The (perceived) performance for the visitors of web pages** hosted using Servus is the most important.

As mentioned above, the web browser does not need to run any client-side code or make any additional requests to get the full experience! Plain HTML, CSS + any images, etc... It is also very easy to put a CDN in front of Servus and make requests even faster because of this very reason (static pages with no dependence on external requests)!

**Servus** does **not** aim to be a performant general-purpose Nostr relay - one that can efficiently ingest huge numbers of events, execute random queries or stream back events for subscriptions in real-time. There are others much better at that!

The *Nostr relay* offered by Servus is very limited! It should be **fast to get all events belonging to a website**... but it may be slow or even impossible to make more complex queries. Also, you don't get streaming of new events coming in after a query has been issued! After existing events are returned as response to a query, you get [`EOSE`](https://github.com/nostr-protocol/nips/blob/master/01.md) and the connection is closed. The client needs to open a new connection and make a new query later in the future if it wants to get new events.

## Status

While **Servus** has quite a few features that may look like "advanced" and I use it personally to serve a couple of web sites, it is also still very much experimental and definitely not for everyone - especially not for beginners!

In order to use it, you need at least some basic understanding of:

* the Linux command line
* DNS

You also need a VPS with SSH access where you would run **Servus** unless you are just curious and want to test it locally.

**Also keep in mind that everything changes all the time without prior notice!** So using it for a production website is very risky. For now...

### Beginners

Does the above sound complicated to you?

**You might want to stop here, bookmark this repo, and check back in a year.**

Things are definitely going to improve, but for now I am too busy building a solid foundation in order to consider beginners. Sorry.

### Themes

**Servus** uses Zola themes. First time you run **Servus** it will ask you whether you want to download the themes and while downloading them it will check which ones actually work (not all themes work yet).

## Try it out

It's very simple to get up and running!

### On Linux

 * `wget https://github.com/servuscms/servus/releases/latest/download/servus-linux.tar.gz`
 * `tar xzfv servus-linux.tar.gz`
 * `./servus`

This will work both locally and on a bare VPS (you can use its public IP address or DNS domain to access the site)!

### On Windows or OSX

Windows and OSX builds are also available from the GitHub [release page](https://github.com/servuscms/servus/releases/latest)! Download, unzip and run it from a terminal.

### Building from source

* `cargo build` - this builds the "debug" version under `target/debug`, which you can execute it using `./target/debug/servus`
* `cargo build --release` - this builds the "release" version under `target/release`
* `docker run --rm -it -v "$PWD":/home/rust/src messense/rust-musl-cross:x86_64-musl cargo build --release` - this is an alternative way to build with musl

## Usage

* `cd target/debug` or `cd target/release` if you have built from source
* `./servus` - this starts **Servus** on port 4884, without SSL
* `sudo ./servus --ssl-acme[-production] --contact-email <contact_email>` - this starts **Servus** on port 443 and obtains SSL certificates from Let's Encrypt using ACME by providing `<contact_email>`
* `sudo ./servus --ssl-cert <SSL_CERT_FILE> --ssl-key <SSL_KEY>` - this starts **Servus** on port 443 using the provided `<SSL_CERT>` and `<SSL_KEY>`. Certificates can be obtained using [acme.sh](https://github.com/acmesh-official/acme.sh), but make sure you run `acme.sh --to-pkcs8` to convert the key to PKCS8 before you pass it to **Servus**.

Note the `sudo` required to bind to port 443! Other ports can be used by passing `-p`, whether in SSL mode or not!

NB: in order to obtain Let's Encrypt certificates you must be running Servus on a machine that is accessible via a public IP (such as a VPS) and have the domain name mapped to that machine's IP. Running the `--ssl-acme` version on your developement machine won't work because Let's Encrypt will try to actually connect to your domain and validate your setup.

PS: You can try running the SSL version locally using a custom certificate by passing `--ssl-cert` and `--ssl-key` if you map `127.0.0.1` to your domain name from `/etc/hosts` and get a realistic simulation of the live environment on your local machine!

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
│   ├── data
│   │   ├── data1.yml
│   │   └── [...]
│   ├── notes
│   │   ├── note1.md
│   │   └── [...]
│   ├── pages
│   │   ├── page1.md
│   │   └── [...]
│   └── posts
│       ├── yyyy-mm-dd-post1.md
│       └── [...]
├── favicon.ico
└── [...]
```

Files and directories starting with "." are ignored.

Files and directories starting with "_" have special meaning: `_config.toml`, `_content`.

Anything else will be directly served to the clients requesting it.

## _config.toml

Required: `base_url`, `theme`.

Optional: `pubkey`, `title`.

`pubkey`, if specified, is used to enable posting using the Nostr protocol. Only events from the specified pubkey will be accepted, after validating the signature.

## Templating

Templating is handled by `Tera`, which should look familiar to anyone who has used Liquid or Jinja2. See Tera's [documentation](https://tera.netlify.app/docs/) for more details.

## Template variables

The following variables are passed to the templates:

* `data` - any data loaded from YAML files in `_content/data/`
* `posts` - a list of all the posts
* `page` - the current resource (post / page / note) being rendered
* `servus.version` - the version of Servus currently running
* `config` - the values specified in `_config.toml`
* `page.url`, `page.slug`, `page.summary`, `page.date`, ...

## Managing your content

**Post to your site using any Nostr client** such as [Amethyst](https://github.com/vitorpamplona/amethyst).

## REST API

A simple REST API exists that can be used to create new sites and list sites associated with a Nostr pubkey.

### `/api/sites`

A `POST` to `/api/sites` can be used to add a new site associated with a key.

A `GET` to `/api/sites` can be used to get a list of all the sites belonging to a key.

### `/api/config`

A `GET` to `/api/config` will return the list of available themes and the currently selected theme.

A `PUT` to `/api/config` can be used to change the site's theme.

NB: All requests require a [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) authorization header to be present!

## Blossom API

Servus implements the [Blossom API](https://github.com/hzrd149/blossom) and therefore acts as your personal Blossom server.

* PUT `/upload`
* GET `/list/<pubkey>`
* DELETE `/<sha256>`

## NIP-96 API

Servus implements [NIP-96](https://github.com/nostr-protocol/nips/blob/master/96.md) file storage.

* POST `/api/files`
* DELETE `/api/files/<sha256>`

## Admin interface

The *admin interface* is rudimentary at best and lets you create sites and change a site's theme (using the Servus REST API). It requires you to have a Nostr extension such as [Alby](https://getalby.com/) or [nos2x](https://github.com/fiatjaf/nos2x) installed in your browser. You might as well not use it and just change your site's theme by editing `_config.toml` and restarting **Servus**.

## Any questions?

If you read this far without giving up and still want to try it yourself, feel free to open GitHub issues with any problems you encounter and I'll try to help!
