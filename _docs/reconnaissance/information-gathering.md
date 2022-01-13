---
title: Information Gathering
category: Reconnaissance
order: 1
---

Information Gathering is the act of gathering different kinds of informationagainst the targeted victim or system.

There are two types of information gathering, **passive** or OSINT (Open Source INTelligence) information gathering which means gathering as much information about our target wihout exposing our presence, and **active** information gathering which techniques interact directly with the target system.

# Passive Information Gathering (OSINT)

Is a technique to gather information without any interaction with the target. There are many tools that are listed in OSINT Framework.

## OSINT Framework

The OSINT Framework includes information gathering tools and websites in one central location. Some tools listed in the framework cover more disciplines than information security.

![OSINT Framework](/hackingnotes/images/osint.png)

* [https://osintframework.com/](https://osintframework.com/)

## Search Engines

Google offers the opportunity to perform advanced search queries using special operators:

`AND, OR, +, -, ""`

And this is some examples of queries:

| Query Type | Google Dork           |
| ---------- | --------------------- |
| Cache      | cache:www.example.com |
| Link       | link:www.example.com  |
| Site       | site:www.website.com  |
| Filetype   | filetype:pdf          |
| Title      | intitle:index.of      |

# Harvesting

Harversting is extract information from documents and files. We can find information such as emails, workers and so on. theHarvester is a tool that automates this working

```
theharvester -d example.com -b google
theharvester -d example.com -b linkedin
```

## Social Media

The spread of social networks has made information gathering extremely important and effective. With the help of social media, a pentester can esaily gather employee's personal informacion such as phone numbers, addresses, history and CV.

We want to collect the following information about the employees:

* Age
* Phone Number
* Addresses
* Occupation
* Business
* Interests
* Email Addresses
* Website Owned
* Related Documents
* Financial Info

# Infrastructures

The main goal here is to retrieve data such as:

* Domains
* Netblocks or IP addresses
* Mail servers
* ISP's used (Internet Server Provider)
* Any other technical information

## Domains and subdomains

Given a domain, the first source for information is [WHOIS](https://tools.ietf.org/html/rfc3912). There are a lot of online tools that allow you top use WHOIS:

* [http://who.is](https://who.is)
* [http://whois.domaintools.com](https://whois.domaintools.com)
* [https://www.betterwhois.com/](https://www.betterwhois.com)
* [https://searchdns.netcraft.com/](https://searchdns.netcraft.com)

There are some tools that search subdomains like `amass` or `sublist3r`:

```
sublist3r -d [Domain]
amass enum -d example.com
```

**Nmmapper** is an online tool that finds a lots of subdomains:

* [https://www.nmmapper.com/sys/tools/subdomainfinder/](https://www.nmmapper.com/sys/tools/subdomainfinder/)

The following user guide helps us a lot to inspect some awesome queries.

* [https://github.com/OWASP/Amass/blob/master/doc/user_guide.md](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md)

## Recon-ng

Recon-ng is a moduled-base framework for web-based information gathering. Recon-ng displays the results of a module to the terminal but it also stores them in a database.

### Searching Modules

We can add modules from the recon-ng with marketplace.

```
marketplace search <MODULE>
marketplace info <MODULE>
marketplace install <MODULE>
```

### Using Modules

We need to load the module before using it:

```
marketplace load <MODULE>
info
options set <OPTION> <VALUE>
```

### Display results

We can display some different results, since hosts to vulnerabilities.

```
show #To see all posibilities of displaying
show <SELECTION>
```

### Best Recon-ng Modules

```
recon/domains-hosts/google_site_web #Search subdomains on Google with Google Dorks
recon/hosts-hosts/resolve #Update hosts table with the DNS resolution
```

## Shodan

As we gather information on our target, it is important to remember that traditional websites are just one part of the internet. [Shodan ](https://www.shodan.io)is a search engine that crawls devices connected to the internet.

![Shodan search.](/hackingnotes/images/shodan.png)

The following repository gives us some examples of what we can do with this brilliant tool

* [https://github.com/jakejarvis/awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries)

# Open-Source Code

One such of interesting information are open-source projects and online code repositories, such as GitHub, GitLab and SourceForge.

## GitLeaks

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an **easy-to-use, all-in-one solution** for finding secrets, past or present, in your code.

```
gitleaks --repo-url=https://github.com/my-insecure/repo -v
```
* [https://github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks)