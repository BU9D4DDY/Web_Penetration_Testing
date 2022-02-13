- [ ] Verify the target’s **scope**

- [ ] Manually Walking Through the Target.

- [ ] Getting Top-level domains

    - [ ] WHOIS  `$ whois domain.com`
    - [ ] Reverse-WHOIS  **[ViewDNS.info](https://viewdns.info/reversewhois/)** 
    - [ ] Find the IP address of the domain  `$ nslookup domain.com`
    - [ ] Reverse IP lookup  **[ViewDNS.info](https://viewdns.info/reversewhois/)** also `$ whois IP ` to get the IP NetRange 

- [ ] Certificate Parsing  

    - [ ] Use online databases like [crt.sh](https://crt.sh/), [Censys](https://censys.io/), and [Cert Spotter](https://sslmate.com/certspotter/) to find certificates for a domain.

        >  add the URL parameter output=json to the request URL: https://crt.sh/?q=domain.com&output=json.

- [ ] Detect WAF

    - [ ]  
    - [ ]  
    - [ ] 

- [ ] Subdomain Enumeration

    - [ ]  
    - [ ]  
    - [ ]  
    - [ ]  
    - [ ]  
    - [ ]   
    - [ ]  
    - [ ]  
    - [ ] combine multiple files containing subs`$ sort -u sublist1.txt sublist2.txt > allsubs.txt` 

- [ ] Service Enumeration (port-scanning)

    - [ ] `Nmap `or `Masscan `for active scanning
    - [ ]  `Shodan` and `Censys` and `Project Sonar` for passive scanning

- [ ] Directory Brute-Forcing

    - [ ]  `Dirsearch` or` Gobuster`
    - [ ]  *screenshot* tool like [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness/) or [**Snapper**](https://github.com/dxa4481/Snapper/)
    - [ ] 
    - [ ]  

- [ ] Spidering the Site via ZAP or Burp Suite

- [ ] Third-Party Hosting

    - [ ] S3 buckets Google Dork

        ```
        site:domain.com inurl:BUCKET.s3.amazonaws.com
        site:domain.com inurl:s3.amazonaws.com/BUCKET
        site:BUCKET.s3.amazonaws.com COMPANY_NAME
        site:s3.amazonaws.com/BUCKET COMPANY_NAME
        
        amazonaws s3 COMPANY_NAME
        amazonaws BUCKET COMPANY_NAME
        amazonaws COMPANY_NAME
        s3 COMPANY_NAME
        ```

    - [ ] [GrayhatWarfare](https://buckets.grayhatwarfare.com/)

    - [ ] [Lazys3](https://github.com/nahamsec/lazys3/)

    - [ ] [Bucket Stream](https://github.com/eth0izzle/bucket-stream)

    - [ ] check accessibility using AWS command line tool

        ```bash
        aws s3 ls s3://BUCKET_NAME
        aws s3 cp s3://BUCKET_NAME/ANY_FILE_NAME_PATH
        ```

- [ ] Dorking ( GitHub - Google)

- [ ] Pastebin Dorking --> [PasteHunter](https://github.com/kevthehermit/PasteHunter/) 

- [ ] Tech Stack Fingerprinting

    - [ ] `Wappalyzer`,  [BuiltWith](https://builtwith.com/), 
    - [ ] **Retire.js** tool to detect outdated JavaScript libraries and Node.js packages. 
    - [ ] run `Nmap `on a machine with the `-sV` flag on to enable version detection on the port scan. 
    - [ ] Next, in Burp, send an HTTP request to the server to check the HTTP headers used to gain insight into the tech stack.

- [ ] check robots.txt

- [ ] check html code

