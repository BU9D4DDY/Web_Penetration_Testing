# Google **Dorking**

Advanced Google searches are a powerful technique that hackers often use to perform recon.

Google can be a means of discovering valuable information such as hidden admin portals, unlocked password files, and leaked authentication keys.

There is a nice and big list of popular and fresh Google Dorks called [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) .

Here are some of the most useful operators that can be used with any Google search:

- site Tells Google to show you results from a certain site only.

- inurl Searches for pages with a URL that match the search string. It’s a powerful way to search for vulnerable pages on a particular website. `inurl:"/course/jumpto.php" site:example.com.`

- intitle Finds specific strings in a page’s title. This is useful because it allows you to find pages that contain a particular type of content. `intitle:"index of" site:example.com.`

- link

    Searches for web pages that contain links to a specified URL. You can use this to find documentation about obscure technologies or vulnerabilities.

    `link:"[<https://en.wikipedia.org/wiki/ReDoS>](<https://en.wikipedia.org/wiki/ReDoS>)"`

- filetype

    Searches for pages with a specific file extension. This is an incredible tool for hacking; hackers often use it to locate files on their target sites that might be sensitive, such as log and password files. `filetype:log site:example.com.`

- Wildcard (*)

    You can use the wildcard operator (*) within searches to mean any character or series of characters.

- Quotes (" ") Adding quotation marks around your search terms forces an exact match.

- Or ( | )

    The or operator is denoted with the pipe character (|) and can be used to search for one search term or the other, or both at the same time. The pipe character must be surrounded by spaces.

- Minus (-)

    The minus operator (-) excludes certain search results. For example, let’s say you’re interested in learning about websites that discuss hacking, but not those that discuss hacking PHP. This query will search for pages that contain how to hack websites but not php:

    `"how to hack websites" -php.`

These operators can be more useful. For example, **look for all of a company’s subdomains by searching as follows:**  `site:*.example.com`

Look for special extensions that could indicate a sensitive file. In addition to .log, which often indicates log files, search for `.php, cfm, asp, .jsp, and .pl`, the extensions often used for script files: `site:example.com ext:php` `site:example.com ext:log`

Finally, you can also combine search terms for a more accurate search. For example, this query searches the site example.com for text files that contain password: `site:example.com ext:txt password`

#### **And Here is a list of most of google dorks ..!**

> https://github.com/BullsEye0/google_dork_list
>
> https://github.com/thomasdesr/Google-dorks

#### **The process of google dorking can be automated using any of these tools**

> https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan
>
> https://dorks.faisalahmed.me/#
>
> https://github.com/TheSpeedX/SDorker
>
> https://github.com/m3n0sd0n4ld/uDork
>
> https://github.com/BullsEye0/dorks-eye
>
> https://github.com/TebbaaX/Katana
>
> https://github.com/Hood3dRob1n/BinGoo
>
> https://github.com/opsdisk/pagodo
>
> https://github.com/Ranginang67/M-dork
>
> https://github.com/dievus/msdorkdump
>
> https://github.com/hhhrrrttt222111/Dorkify
>
> https://github.com/utiso/dorkbot
>
> https://github.com/dwisiswant0/go-dork
>
> https://github.com/rly0nheart/oxdork
>
> https://github.com/USSCltd/dorks
>
> https://github.com/nerrorsec/GoogleDorker
>
> https://github.com/cipher387/Dorks-collections-list

##### Below I share with you some of the interesting Google Dorks I used in the past (one Google Dork per line):

```
allintext: “Pixie Powered”
“script_filename” “HTTP Headers Information” “allow_url_fopen” ext:php
intitle:”Index of” “/ .WNCRY”
inurl:/help/readme.nsf intitle:”release notes” intitle:domino
“Apache Server Status for” “Server Version” -“How to” -Guide -Tuning
inurl:”/web.config” ext:config
inurl:logs/gravityforms
“not for public release” filetype:pdf
“pcANYWHERE EXPRESS Java Client”
wwwboard WebAdmin inurl:passwd.txt wwwboard|webadmin
filetype:pem “PRIVATE KEY”
inurl:/t/ (portal OR intranet OR login)
intitle:”index of” “places.sqlite” “key3.db” -mozilla.org
inurl:”?db_backup” | inurl:”dbbackup” -site:<http://github.com>  “sql.gz” | “sql.tgz” | “sql.tar” | “sql.7z”
inurl:.php? intext:CHARACTER_SETS,COLLATIONS intitle:”phpmyadmin”
intitle:”=[ 1n73ct10n privat shell ]=”
filetype:rdp password
filetype:sh inurl:cgi-bin
allinurl:index.php?db=information_schema
inurl:index.rb
ext:json OR inurl:format=json
inurl:”server-status” intitle:”Apache Status” intext:”Apache Server Status for”
inurl:”.s3.amazonaws.com/”
site:<http://s3.amazonaws.com>  
intitle:index.of.bucketsite:<http://blob.core.windows.net`>
site:* inurl:/user/register
intext:”There isn’t a Github Pages site here”
intitle:”Site not found · GitHub Pages”
inurl:%26 inurl:%3D
inurl:& inurl:%3D
intitle:”Dashboard [Hudson]”
intitle:”Dashboard [Jenkins]” intext:”Manage Jenkins”
“or greater is required”+”You have no flash plugin installed”
site:target.com filetype:”xls | xlsx | doc | docx | ppt | pptx | pdf”
```
