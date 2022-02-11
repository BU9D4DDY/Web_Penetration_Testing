**GitHub** contains a lot of sensitive information which can be useful for an attacker like API keys, passwords, customer data etc. This sensitive information leaks can cost a company thousand dollars of damage.

![GitHub](../../_resources/GitHub.jpg)

Leaks usually fall into one of these categories (ranked from most to least impactful):

1. **SaaS API keys** - Companies rarely impose IP restrictions on APIs. AWS, Slack, Google, and other API keys are liquid gold. These are usually found in config files, bash history files, and scripts.
2. **Server/database credentials** - These are usually behind a firewall, so they're less impactful. Usually found in config files, bash history files, and scripts.
3. **Customer/employee information** - These hide in XLSX, CSV, and XML files and range from emails all the way to billing information and employee performance reviews.
4. **Data science scripts** - SQL queries, R scripts, and Jupyter projects can reveal sensitive information. These repos also tend to have "test data" files hanging around.
5. **Hostnames/metadata** - The most common result. Most companies don't consider this a vulnerability, but they can help refine future searches

![GitHub](../../_resources/E.png)

GitHub Recon can be accomplished manually or by automation using some tools.

1. **Manual - Code Search || GitHub Dorking**

Code search is nothing but the use of some keywords that helps you to find sensitive things like passwords, API keys, database files etc.

![img](../../_resources/1.png)

**How to do a recon on GitHub ?**

1. You can use simple queries like`facebook.com` or google.com etc. to search for a particular company.

![img](../../_resources/2.png)

2. You can also use multi-word strings like **`“Authorization: Bearer”`**

![img](../../_resources/w.png)

Now you need to open a repository and have to search for the authorization token or password or any other sensitive information.

![img](../../_resources/d.png)

3. You can search for specific filenames like `“filename:vim_settings.xml”`

![img](../../_resources/Ow.png)

4. You can search for specific languages like `“language:PHP”`

![img](../../_resources/kQ.png)

This was the basics of the github dorking but you can also combine your queries like **`“facebook.com filename:vim_settings.xml”`** which will give you all the vim_settings.xml file of a particular company Facebook. Same way you can also perform different query searches.

Apart from repositories you can also check for **code**, commits, issues, discussions, packages, marketplace, **topics**, **wikis** and **users.**

![img](../../_resources/y6Og.png)

You should be looking for URLs, API keys, usernames, passwords etc. It might be possible that someone has uploaded something sensitive.

**GitHub Dork List :**

> https://github.com/jcesarstef/ghhdb-Github-Hacking-Database
>
> https://github.com/litt1eb0yy/Awesome-Dorks/blob/master/github-dorks.txt
>
> https://github.com/vinaysonavane/GitHubDorks
>
> https://github.com/hariyopmail/Git-dorks-secrets
>
> https://gist.github.com/EdOverflow/8bd2faad513626c413b8fc6e9d955669

![img](../../_resources/hacks.png)

```
**Specific Org search**

"Org_name" password
"org_name" key
"org_name" api
"org_name" “filename:vim_settings.xml”
"org_name" "Authorization: Bearer"
"org_name" "Language: PHP"
"Company name" send_keys or sendkeys
```

Here are some useful GitHub dorks shared by @hunter0x7 for identifying sensitive information related to Amazon AWS cloud:

```
org:Target "bucket_name" 
org:Target "aws_access_key" 
org:Target "aws_secret_key" 
org:Target "S3_BUCKET" 
org:Target "S3_ACCESS_KEY_ID" 
org:Target "S3_SECRET_ACCESS_KEY" 
org:Target "S3_ENDPOINT" 
org:Target "AWS_ACCESS_KEY_ID" 
org:Target "list_aws_accounts"
SSH access Tip "Get config.yaml":
"site . com" ssh language:yaml
```

Here’s another list of GitHub dorks shared by @GodfatherOrwa for identifying various other credentials and secrets:

```
"target.com" password or secret "target.atlassian" password 
"target.okta" password 
"corp.target" password 
"jira.target" password 
"target.onelogin" password 
target.service-now password
```

 Here’s a list of 10 Github dorks to find secret and access tokens:

```
“target.com” send_keys
“target.com” password
“target.com” api_key
“target.com” apikey
“target.com” jira_password
“target.com” root_password
“target.com” access_token
“target.com” config
“target.com” client_secret
“target.com” user auth
```

```
-For aws:
org:Target "bucket_name"
org:Target "aws_access_key"
org:Target "aws_secret_key"
org:Target "S3_BUCKET"
org:Target "S3_ACCESS_KEY_ID"
org:Target "S3_SECRET_ACCESS_KEY"
org:Target "S3_ENDPOINT"
org:Target "AWS_ACCESS_KEY_ID"
org:Target "list_aws_accounts"

-Others:

“target.com” send_keys
“target.com” ldap
“target.com” pwd
“target.com” private_key
“target.com” password
“target.com” api_key
“target.com” apikey
“target.com” jira_password
“target.com” root_password
“target.com” access_token
“target.com” config
"Target" "LdapUsername":
"Target" "ConnectionStrings":
"Target" string _password =
“target.com” client_secret
“target.com” user auth
“target.com”  -----BEGIN DSA PRIVATE KEY-----
“target.com”  -----BEGIN EC PRIVATE KEY-----
“target.com”  -----BEGIN OPENSSH PRIVATE KEY-----
“target.com”  -----BEGIN PGP PRIVATE KEY BLOCK-----

## Extension based search:

- extension:pem private
- extension:ppk private
- extension:sql mysql dump
- extension:sql mysql dump password
- extension:json api.forecast.io
```

```
**GiHub Dorks for Finding API Keys, Tokens and Passwords**

SecretKey / Secrect_key / skey / secret
privatekey / private_key / pkey
user_secret / userSecret
admin_passwd / adminpasswd / adminPass etc
“api keys”
authorization_bearer:
oauth
auth
authentication
client_secret
api_token:
“api token”
send_keys
client_id
password / passwd / pwd 
user_password
user_pass
passcode
client_secret
secret
password hash
OTP
Ldap
private 
user auth
```

```
**GitHub Dorks for Finding Usernames**

user:name (user:admin)
org:name (org:google type:users)
in:login (<username> in:login)
in:name (<username> in:name)
fullname:firstname lastname (fullname:<name> <surname>)
in:email (data in:email)
```

```
**GitHub Dorks for Finding Information using Extension**

extension:pem private
extension:ppk private
extension:sql mysql dump
extension:sql mysql dump password
extension:json api.forecast.io
extension:json mongolab.com
extension:yaml mongolab.com
[WFClient] Password= extension:ica
extension:avastlic “support.avast.com”
extension:json googleusercontent client_secret
```

```
**GitHub Dorks for Finding Information using Extension**

extension:pem private
extension:ppk private
extension:sql mysql dump
extension:sql mysql dump password
extension:json api.forecast.io
extension:json mongolab.com
extension:yaml mongolab.com
[WFClient] Password= extension:ica
extension:avastlic “support.avast.com”
extension:json googleusercontent client_secret
```

```
**GitHub Dorks for Finding Languages**

language:python username
language:php username
language:sql username
language:html password
language:perl password
language:shell username
language:java api
HOMEBREW_GITHUB_API_TOKEN language:shell
```

```
**GitHub Dorks for Finding Information using Dates**

created:<2012–04–05
created:>=2011–06–12
created:2016–02–07 location:iceland
created:2011–04–06..2013–01–14 <user> in:username
```

```
**GitHub Dorks for Finding Files**

filename:manifest.xml
filename:travis.yml
filename:vim_settings.xml
filename:database
filename:prod.exs NOT prod.secret.exs
filename:prod.secret.exs
filename:.npmrc _auth
filename:.dockercfg auth
filename:WebServers.xml
filename:.bash_history <Domain name>
filename:sftp-config.json
filename:sftp.json path:.vscode
filename:secrets.yml password
filename:.esmtprc password
filename:passwd path:etc
filename:dbeaver-data-sources.xml
path:sites databases password
filename:config.php dbpasswd
filename:prod.secret.exs
filename:configuration.php JConfig password
filename:.sh_history
shodan_api_key language:python
filename:shadow path:etc
JEKYLL_GITHUB_TOKEN
filename:proftpdpasswd
filename:.pgpass
filename:idea14.key
filename:hub oauth_token
HEROKU_API_KEY language:json
HEROKU_API_KEY language:shell
SF_USERNAME salesforce
filename:.bash_profile aws
extension:json api.forecast.io
filename:.env MAIL_HOST=smtp.gmail.com
filename:wp-config.php
extension:sql mysql dump
filename:credentials aws_access_key_id
filename:id_rsa or filename:id_dsa
```

So this was all about manual technique to find sensitive information on github, lets move to some automated technique.

2. **Automated Technique - Using Tools**

Sometimes automating the boring tasks can help give you a basic overview of what to look for. It is important to note, that you should never copy and paste findings from scanners into your reports. You will get a lot of false positives, therefore you must always look into the possible issue manually to ensure exploitability.

> https://github.com/gwen001/github-search
>
> https://github.com/hisxo/gitGraber
>
> https://github.com/streaak/keyhacks/
>
> https://github.com/N0MoreSecr3ts/wraith
>
> https://github.com/obheda12/GitDorker
>
> https://github.com/Talkaboutcybersecurity/GitMonitor
>
> https://github.com/techgaun/github-dorks
>
> https://github.com/H4CK3RT3CH/github-dorks
>
> https://github.com/trufflesecurity/truffleHog
>
> https://github.com/Rnalter/SubGitter
>
> https://github.com/Conscript-Security/gitdorker
>
> https://github.com/machinexa2/GithubDorker
>
> https://github.com/alejandro501/github_dork
>
> https://github.com/anshumanbh/git-all-secrets
>
> https://github.com/zricethezav/gitleaks
>
> https://github.com/michenriksen/gitrob
>
> https://github.com/UnkL4b/GitMiner
>
> https://github.com/tillson/git-hound
>
> https://github.com/Hell0W0rld0/Github-Hunter
>
> https://github.com/duo-labs/secret-bridge

##### Sample Target

- **HighlySecureOrganization/SuperSecureWebApp**: https://github.com/HighlySecureOrganization/SuperSecureWebApp

**TIP:**

- Use github + translate if you are searching for leaks for Russian, French .... etc programs. that leads to some good results.

![img](../../_resources/J3jA.jpeg)

- Check Commit Histories

![image](../../_resources/eb5b5.png)

- To start finding sensitive information, identify a target.

    I've found that the best way is to **find domains or subdomains that identify corporate infrastructure.**

    Searching for `company.com` probably won't provide useful results: many companies release audited open-source projects that aren't likely to contain secrets. Less-used domains and subdomains are more interesting. This includes specific hosts like `jira.company.com` as well as more general second-level and lower-level domains. It's more efficient to find a pattern than a single domain: `corp.somecompany.com`, `somecompany.net`, or `companycorp.com` are more likely to appear only in an employee's configuration files.