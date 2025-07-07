**DISCLAIMER:** This project is for ***educational purposes only***. All attacks were performed in a controlled lab environment on intentionally vulnerable web applications. Never use these techniques on unauthorized networks or systems.
<br><br>

The OWASP Top Ten is a widely recognized list that outlines the most critical security risks to web applications. These vulnerabilities (in 2021 version) are:
<br><br>

![image](https://github.com/user-attachments/assets/b8fb34de-edcb-4f75-8256-cdfb8ecb91b6)
<br><br>

**MITRE ATT&CK Mapping:**

<table border="1" cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>OWASP Top 10 (2021) Category</th>
      <th>Mapped MITRE ATT&amp;CK Technique&nbsp;ID&nbsp;&&nbsp;Name</th>
      <th>ATT&amp;CK Tactic(s)</th>
    </tr>
  </thead>

  <tbody>
    <tr>
      <td><strong>1. Broken Access Control</strong></td>
      <td>
        T1078 – Valid Accounts<br>
        T1081 – Credentials in Files<br>
        T1550 – Use Alternate Authentication Material
      </td>
      <td>Initial Access, Persistence, Privilege Escalation</td>
    </tr>
    <tr>
      <td><strong>2. Cryptographic Failures</strong></td>
      <td>
        T1552 – Unsecured Credentials<br>
        T1608.005 – Upload Malicious File<br>
        T1040 – Network Sniffing
      </td>
      <td>Credential Access, Collection</td>
    </tr>
    <tr>
      <td><strong>3. Injection</strong></td>
      <td>
        T1190 – Exploit Public‑Facing Application<br>
        T1505.003 – Server Software Component
      </td>
      <td>Initial Access, Execution</td>
    </tr>
    <tr>
      <td><strong>4. Insecure Design</strong></td>
      <td>
        T1565 – Data Manipulation<br>
        T1556 – Modify Authentication Process
      </td>
      <td>Privilege Escalation, Impact</td>
    </tr>
    <tr>
      <td><strong>5. Security Misconfiguration</strong></td>
      <td>
        T1068 – Exploitation for Privilege Escalation<br>
        T1203 – Exploitation for Client Execution
      </td>
      <td>Execution, Privilege Escalation</td>
    </tr>
    <tr>
      <td><strong>6. Vulnerable &amp; Outdated Components</strong></td>
      <td>
        T1190 – Exploit Public‑Facing Application<br>
        T1210 – Exploitation of Remote Services
      </td>
      <td>Initial Access, Execution</td>
    </tr>
    <tr>
      <td><strong>7. Identification &amp; Authentication Failures</strong></td>
      <td>
        T1110 – Brute Force<br>
        T1556 – Modify Authentication Process<br>
        T1078 – Valid Accounts
      </td>
      <td>Credential Access, Privilege Escalation</td>
    </tr>
    <tr>
      <td><strong>8. Software &amp; Data Integrity Failures</strong></td>
      <td>
        T1195 – Supply Chain Compromise<br>
        T1554 – Compromise Client Software Binary
      </td>
      <td>Initial Access, Execution</td>
    </tr>
    <tr>
      <td><strong>9. Security Logging &amp; Monitoring Failures</strong></td>
      <td>
        T1562.001 – Disable/Modify Security Tools<br>
        T1562.004 – Disable/Modify System Logging
      </td>
      <td>Defense Evasion</td>
    </tr>
    <tr>
      <td><strong>10. Server‑Side Request Forgery (SSRF)</strong></td>
      <td>
        T1213 – Data from Information Repositories<br>
        T1559 – Inter‑Process Communication
      </td>
      <td>Collection, Lateral Movement</td>
    </tr>
  </tbody>
</table>
<br><br>

Here we will demonstrate and exploit each of these vulnerabilities one by one on TryHackMe's OWASP Top 10 - 2021 lab (https://tryhackme.com/room/owasptop102021).
<br><br>

**1) Broken Access Control**

This occurs when applications fail to properly enforce user permissions, allowing attackers to access unauthorized resources or perform restricted actions. Examples include IDOR (Insecure Direct Object Reference) which is a vulnerability that exposes direct references to objects which can be modified by users.

Example:

First we login as a normal user.

![image](https://github.com/user-attachments/assets/d75fbd8b-10e3-49b7-aad4-89428235aa25)

![image](https://github.com/user-attachments/assets/2911e20f-8e31-420c-bb35-ff87b52d32b1)

We try modifying the 'note_id' GET parameter in the URL and change it from 1 to 2.

![image](https://github.com/user-attachments/assets/c82f967b-acc2-4a68-98c3-9acb4e5c6362)

And now we can access the account of some other user! 

We can use burpsuite's intruder feature to brute force possible 'note_id' values in a range and check the output.

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

Mitigation: Disable unused features and services, configure security headers, apply least privilege configurations, keep software updated, and regularly audit and harden system configurations.
<br><br>

**6) Vulnerable and Outdated Components**







