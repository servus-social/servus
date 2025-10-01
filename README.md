# Servus

![logo](https://github.com/servus-social/servus/blob/master/logo.png?raw=true)

## About

**Servus** is a minimalist **social media server** fully self-contained within one executable file.

- [x] CMS
- [x] Personal Nostr relay
- [x] Personal Blossom server
- [x] [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) ("Nostr address") server

### CMS

As a CMS, Servus sits somewhere in between Jekyll and WordPress.

Like Jekyll:
 * all content is stored in flat files

Unlike Jekyll:
 * no build step
 * no need to manually edit the files
 * no need to configure a web server
 * no dependencies on Ruby Gems, Docker, etc.

Like WordPress:
 * easy administration (use any Nostr client as your "admin interface")

Unlike WordPress:
 * no need to run a database server, like MySQL
 * no need to run a web server, like Apache

### Personal Nostr Relay & Blossom server

 - [x] own your identity
 - [x] own your data

If you already have a Nostr keypair, you already own your identity. But you only really own your data when you self-host it. You can't rely on other relays to store your data forever.

[Blossom](https://github.com/hzrd149/blossom) is a protocol adjacent to Nostr that specifies how files (such as images) are to be stored on HTTP servers.

## Features

* **Single executable** that you can `scp` to a bare VPS and it will just work. Without Docker, without MySQL, without Python venv, without Node or PHP, without setting up an nginx reverse proxy and whatnot... You shouldn't need any of that to self-host your personal website!
* All content and settings stored as **plain text**. Except, of course, images or other media you have as content. Not in a SQL database, not in "the cloud", not in "some Nostr relays"... but in plain text files on the machine running Servus.
* As a corolary of the above, a *full backup* is just an `rsync` command... or a `.zip` file. That's all your data! Download a copy of it to your laptop, write a script that imports it to another CMS, search it, feed it to your favourite LLM...
* All content served to the readers is **plain HTML served over HTTP(S)**. No Javascript that generates UI elements on the client side, no Javascript that queries Nostr relays or uses background HTTP requests to get content from the server. What you get is a plain "website" that you can open in any web browser or even using `wget`.
* **Support for themes**. *Simple* doesn't mean ugly nor does it mean it should be limited in any way. Avoiding unnecessary client-side technologies doesn't mean the websites built using Servus need to look "old school" or be limited in functionality. In fact, themes *can* use Javascript *if they want to* - for certain effects, etc. The goal is to not *require* Javascript as part of the overall architecture, not to avoid it at any cost.
* **Multiple websites** that can be separately administered in one instance. So you will be able to, for example, self-host your personal website, your business's website and have your uncle host his blog, all with a single Servus instance.

## Performance and limitations

As mentioned above, the web browser does not need to run any client-side code or make any additional requests to get the full experience! Plain HTML, CSS + any images, etc... It is also very easy to put a CDN in front of Servus and make requests even faster because of this very reason (static pages with no dependence on external requests)!

However, **Servus** does **not** aim to be a performant general-purpose Nostr relay - one that can efficiently ingest huge numbers of events, execute random queries or stream back events for subscriptions in real-time. There are others much better at that!

## Status

While **Servus** has quite a few features that may look like "advanced" and I use it personally to serve a couple of web sites, it is also still very much experimental and definitely not for everyone - especially not for beginners!

In order to use it, you need at least some basic understanding of:

* the Linux command line
* DNS

You also need a VPS with SSH access where you would run **Servus** unless you are just curious and want to test it locally.

**Also keep in mind that everything changes all the time without prior notice!** So using it for a production website is very risky. For now...

Does the above sound complicated to you?

**You might want to stop here, bookmark this repo, and check back in a year.** Things are definitely going to improve.

## Try it out

 * `wget https://github.com/servuscms/servus/releases/latest/download/servus-linux.tar.gz`
 * `tar xzfv servus-linux.tar.gz`
 * `./servus`

This will work both locally and on a bare VPS (you can use its public IP address or DNS domain to access the site)!

## Command line

* `sudo ./servus --ssl-acme[-production] --contact-email <contact_email>` - this starts **Servus** on port 443 and obtains SSL certificates from Let's Encrypt using ACME by providing `<contact_email>`
* `sudo ./servus --ssl-cert <SSL_CERT_FILE> --ssl-key <SSL_KEY>` - this starts **Servus** on port 443 using the provided `<SSL_CERT>` and `<SSL_KEY>`. Certificates can be obtained using [acme.sh](https://github.com/acmesh-official/acme.sh), but make sure you run `acme.sh --to-pkcs8` to convert the key to PKCS8 before you pass it to **Servus**.

Note the `sudo` required to bind to port 443! Other ports can be used by passing `-p`, whether in SSL mode or not!

NB: in order to obtain Let's Encrypt certificates you must be running Servus on a machine that is accessible via a public IP (such as a VPS) and have the domain name mapped to that machine's IP. Running the `--ssl-acme` version on your developement machine won't work because Let's Encrypt will try to actually connect to your domain and validate your setup.

PS: You can try running the SSL version locally using a custom certificate by passing `--ssl-cert` and `--ssl-key` if you map `127.0.0.1` to your domain name from `/etc/hosts` and get a realistic simulation of the live environment on your local machine!

## Importing your content

When creating a new site you are asked whether you want to import your Instagram content. You can get a dump of all your Instagram data from the app and Servus will happily import all your pictures. Great way to get started with an old school photoblog that you can self-host (and is Nostr ready)!

## Managing your content

**Post using any Nostr client** such as [YakiHonne](https://yakihonne.com/) (they have good mobile apps!).

## Admin interface

The *admin interface* is rudimentary and lets you create sites and change a site's theme (using the Servus REST API). It requires you to have a Nostr extension such as [Alby](https://getalby.com/) or [nos2x](https://github.com/fiatjaf/nos2x) installed in your browser. You can also bypass the admin interface and change your site's theme by editing `_config.toml` and restarting **Servus**.

## More info

* [API](https://github.com/servus-social/servus/blob/master/docs/api.md)
* [Build](https://github.com/servus-social/servus/blob/master/docs/build.md)
* [Content](https://github.com/servus-social/servus/blob/master/docs/content.md)
* [Templates](https://github.com/servus-social/servus/blob/master/docs/templates.md)

## Any questions?

If you read this far without giving up and still want to try it yourself, feel free to open GitHub issues with any problems you encounter and I'll try to help!
