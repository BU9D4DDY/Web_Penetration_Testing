# Bug Bounty Dorks

List of Google Dorks to search for companies that have a responsible disclosure program or bug bounty program which are not affiliated with known bug bounty platforms such as HackerOne or Bugcrowd.

```
inurl /bug bounty
inurl : / security
inurl:security.txt
inurl:security "reward"
inurl : /responsible disclosure
inurl : /responsible-disclosure/ reward
inurl : / responsible-disclosure/ swag
inurl : / responsible-disclosure/ bounty
inurl:'/responsible disclosure' hoodie
responsible disclosure swag r=h:com
responsible disclosure hall of fame
responsible disclosure europe
responsible disclosure white hat
white hat program
insite:"responsible disclosure" -inurl:nl
intext responsible disclosure
site eu responsible disclosure
site .nl responsible disclosure
site responsible disclosure
responsible disclosure:sites
responsible disclosure r=h:nl
responsible disclosure r=h:uk
responsible disclosure r=h:eu
responsible disclosure bounty r=h:nl
responsible disclosure bounty r=h:uk
responsible disclosure bounty r=h:eu
responsible disclosure swag r=h:nl
responsible disclosure swag r=h:uk
responsible disclosure swag r=h:eu
responsible disclosure reward r=h:nl
responsible disclosure reward r=h:uk
responsible disclosure reward r=h:eu
"powered by bugcrowd" -site:bugcrowd.com
"submit vulnerability report"
site:*.gov.* "responsible disclosure"
intext:"we take security very seriously"
site:responsibledisclosure.com
inurl:'vulnerability-disclosure-policy' reward
intext:Vulnerability Disclosure site:nl
intext:Vulnerability Disclosure site:eu
site:*.*.nl intext:security report reward
site:*.*.nl intext:responsible disclosure reward
"security vulnerability" "report"
inurl"security report"
"responsible disclosure" university
inurl:/responsible-disclosure/ university
buy bitcoins "bug bounty"
inurl:/security ext:txt "contact"
"powered by synack"
intext:responsible disclosure bounty
inurl: private bugbountyprogram
inurl:/.well-known/security ext:txt
inurl:/.well-known/security ext:txt intext:hackerone
inurl:/.well-known/security ext:txt -hackerone -bugcrowd -synack -openbugbounty
inurl:reporting-security-issues
inurl:security-policy.txt ext:txt
site:*.*.* inurl:bug inurl:bounty
site:help.*.* inurl:bounty
site:support.*.* intext:security report reward
intext:security report monetary inurl:security 
intext:security report reward inurl:report
site:security.*.* inurl: bounty
site:*.*.de inurl:bug inurl:bounty
site:*.*.uk intext:security report reward
site:*.*.cn intext:security report reward
"vulnerability reporting policy"
"van de melding met een minimum van een" -site:responsibledisclosure.nl
inurl:/security ext:txt "contact"
inurl:responsible-disclosure-policy
"If you believe you've found a security vulnerability"
intext:"BugBounty" and intext:"BTC" and intext:"reward"
intext:bounty inurl:/security
inurl:"bug bounty" and intext:"€" and inurl:/security
inurl:"bug bounty" and intext:"$" and inurl:/security
inurl:"bug bounty" and intext:"INR" and inurl:/security
inurl:/security.txt "mailto*" -github.com  -wikipedia.org -portswigger.net -magento
/trust/report-a-vulnerability
site:*.edu intext:security report vulnerability
"cms" bug bounty
"If you find a security issue"  "reward"
"responsible disclosure" intext:"you may be eligible for monetary compensation"
inurl: "responsible disclosure", "bug bounty", "bugbounty"
responsible disclosure inurl:in
site:*.br responsible disclosure
site:*.at responsible disclosure
site:*.be responsible disclosure
site:*.au responsible disclosure
```

And Here is a word file containing about 7.5K bounty programs

> https://drive.google.com/file/d/1Ui19rhJ5ER0ZS2_6HQSFp3YJmV6yWUNP/view

TIP:

- Gather domains from content-security-policy @geeknik

    ```bash
    curl -v -silent https://$domain --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
    ```

    -- Try To change "content-security-policy" with some other dorks...

## Bug Bounty Platforms

> [Bug Bounty Platforms | MindMeister](https://www.mindmeister.com/1578309575/bug-bounty-platforms?fullscreen=1#)
>
> https://github.com/disclose/bug-bounty-platforms

**Open For Signup**

| [Bugcrowd](https://www.bugcrowd.com/)           | [BountyFactory](https://bountyfactory.io/) | [BugbountyHQ](https://www.bugbountyhq.com/) |
| ----------------------------------------------- | ------------------------------------------ | ------------------------------------------- |
| [HackerOne](https://www.hackerone.com/)         | [Intigriti](https://intigriti.be/)         | [Hackerhive](https://hackerhive.io/)        |
| [OpenBugBounty](https://www.openbugbounty.org/) | [Bugbountyjp](https://bugbounty.jp/)       | [Hackenproof](https://hackenproof.com/)     |
| [YesWeHack](https://www.yeswehack.com/)         | [Safehats](https://safehats.com/)          | [Hacktrophy](https://hacktrophy.com/)       |

**Invite Based Platforms**

| [Synack](https://www.synack.com/red-team/) | [Zerocopter](https://zerocopter.com/)  | [Bugbountyzone](https://bugbountyzone.com/) |
| ------------------------------------------ | -------------------------------------- | ------------------------------------------- |
| [Cobalt](https://cobalt.io/)               | [Antihack.me](http://www.antihack.me/) | [Vulnscope](https://www.vulnscope.com/)     |
| [Yogosha](https://www.yogosha.com/)        |                                        |                                             |

