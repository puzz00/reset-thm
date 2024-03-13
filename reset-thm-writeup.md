The [reset](https://tryhackme.com/room/resetui) box is a great active directory room found on [thm](https://tryhackme.com) We get to mess about in an active directory environment and there is a fun watering hole attack to be found, too... :smiling_imp: 

## port scanning

We can start with an nmap scan which shows us that the target machine is probably a domain controller since it has port 88 open - this port is used for kerberos :dog: :dog: :dog: authentication traffic.

`ports19=$(sudo nmap -n -Pn -p- --min-rate=250 -sS --open 10.10.181.19 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`

`echo $ports19 > p19.txt`

![nmap1](/images/1.png)

When we scan the open tcp ports more intensely, we get some data about the domain and the machine we are attacking. We also notice that port 5985 is open - this is of interest as it is a port which is used by *winrm* which in turn is a service which could give us a shell if we find valid credentials.

`sudo nmap -Pn -n -p$ports19 -sV -A 10.10.181.19`

![nmap2](/images/2.png)

---

## smb enumeration

Since smb is being used, we can start our enumeration of the box with it - can we get a null session and thereby enumerate useful data? :thinking: We find that we can!

The IPC$ share has read access for non-authenticated users such as ourselves - we can use this to bruteforce valid usernames. There is a non-default share called *Data* which also allows non-authenticated users read access which means we can enumerate it for anything which is interesting or useful. The *Data* share curiously allows non-authenticated users to write to it which could well be of use later on...

`sudo smbmap -H 10.10.152.174 -u 'guest' -p ''`

![smb1](/images/3.png)

We have a look into the *Data* share and find two pdf files along with a txt file. We can download these using smbclient and have a look at them. We are able to retreive a possible username:password combination by taking the time to carefully look through them.

> [!IMPORTANT]
> We need to escape \ when enumerating windows systems from a linux command line

---

`sudo smbclient \\\\10.10.152.174\\Data -U THM.corp\\guest`

---

`cd onboarding`

---

`mget *.pdf`

---

![smb2](/images/6.png)

---

## bruteforcing usernames

We can use *crackmapexec* to brute force user names since we have read access to the IPC$ share as an anonymous user.

`sudo crackmapexec smb 10.10.152.174 -u 'guest' -d thm.local -p '' --rid-brute`

![usernames1](/images/4.png)

![usernames2](/images/5.png)

We can also use the *impacket* tool called *lookupsid.py* We can use bash commands with this tool to create a list of usernames.

`sudo python3 lookupsid.py THM.corp/guest@10.10.181.19 | grep -i 'SidTypeUser' | cut -d '\' -f 2 | awk {'print $1'} > usernames.txt`

![usernames3](/images/8b.png)

![usernames4](/images/8c.png)

Before launching a brute force attack, it makes sense to try and enumerate the password policy since we do not want to lock out accounts. In this case, we could not do so, but it is still worth trying as older servers are vulnerable to this kind of enumeration.

`sudo crackmapexec smb 10.10.152.174 -u 'guest' -p '' --pass-pol`

As we can't find out anything about the password policy in place, it makes sense to use a password spraying attack rather than a traditional brute force :hammer: so we run less chance of locking accounts.

> [!IMPORTANT]
> Password spraying is where we use one password against lots of different accounts

`sudo crackmapexec smb 10.10.181.19 -u usernames.txt -p 'ResetMe123!'`

![usernames5](/images/9.png)

![usernames6](/images/10.png)

The valid credentials which we have obtained for the LILY_ONEILL user do not give us access to the target machine :lock: so we need to think of a different way to hack it... 🤔 

---

## as-rep roasting

Thinking again, we come up with an as~~s~~-rep roasting attack. This type of attack takes advantage of the fact that anybody can request a ticket granting ticket :ticket: from the key distribution center for a user account if that account has kerberos pre-authentication disabled. This might seem :zany_face: but it is somethimes necessary - for example if a user needs to access an app which does not support kerberos pre-authentication. Ths useful thing is that a ticket granting ticket is encrypted :key: using a key derived from the user's password. This means that once we have a tgt for a user, we also have a hash to crack which if cracked will give us the user's plaintext password :ghost:

In this case, we receive three hashes and manage to crack one of them.

`sudo python3 GetNPUsers.py THM.corp/ -dc-ip 10.10.152.174 -usersfile usernames.txt -no-pass -request -outputfile hashes.txt`

![asrep1](/images/11.png)

![asrep2](/images/12.png)

`sudo hashcat -a 0 -m 18200 --potfile-path=reset.pot hashes.txt rockyou.txt -O`

![asrep3](/images/13.png)

`sudo hashcat -a 0 -m 18200 --potfile-path=reset.pot hashes.txt rockyou.txt -O --show`

![asrep4](/images/14.png)

The valid credentials which we discover for the user account TABATHA_BRITT do not give us access to the target machine, either :no_entry: 

---

## bloodhound enumeration

We turn to bloodhound since we have found nothing but :door:

After loading *neo4j* and *bloodhound* we can use an ingestor to enumerate the domain further. We can use the creds we have found for TABATHA_BRITT with the ingestor.

`sudo bloodhound-python -d THM.corp -u 'TABATHA_BRITT' -p '<REDACTED>' -ns 10.10.152.174 -c all`

![bloodhound1](/images/15.png)

Once we have obtained the data, we upload it to bloodhound and start to analyze it.

![bloodhound2](/images/16.png)

When we look under *Transitive Object Control* under *Node Info* for the TABATHA_BRITT node, we see some interesting active directory rights.

![bloodhound3](/images/17.png)

![bloodhound4](/images/18.png)

---

### active directory rights

The pictures from bloodhound show us that TABATHA_BRITT has the *GenericAll* right over SHAWNA_BRAY. This right will (amongst other things :stuck_out_tongue:) let TABATHA_BRITT change the password for SHAWNA_BRAY. This is of interest to us because we have pwned TABATHA_BRITT and therefore be able to use their credentials to pwn SHAWNA_BRAY by changing their password :lock: to be under our control :unlock:

Moving on, SHAWNA_BRAY has the ExtendedRight to ForceChangePassword over CRUZ_HALL. This is self-explanatory and will allow us to pwn CRUZ_HALL.

Next in the attack :chains: we see that CRUZ_HALL has the GenericWrite right (write right :confused:) over DARLA_WINTERS. This right will let us change the password for DARLA_WINTERS.

Essentialy, we will be abusing active directory rights. It is always useful when attacking active directory environments to look for these rights (along with several others) as they can enable us to move laterally :arrow_left: :arrow_right: and even sometimes vertically :arrow_up:

Bloodhound is a great tool to use to enumerate active directory rights, but it can be done manually using powershell commands if an initial shell has been obtained.

This is one of the best parts of active directory for an attacker :vampire: - lots of useful domain data can be enumerated even by a low privileged user.

>[!TIP]
>When attacking active directory, we tend to be looking more for misconfiguration of its own functionality than exploits of code

Misconfiguration is not surprising when we consider that active directory is used to manage large collections of assets and humans :zany_face: are involved in said management.

---

## constrained delegation

Moving on, we need to look at DARLA_WINTERS - is there anything special about this object? It turns out that yes there is - DARLA_WINTERS has the ability to delegate via *constrained delegation*.

![cd1](/images/19.png)

![cd2](/images/20.png)

It is possible in active directory to give objects the ability to delegate to services as different users :disguised_face: This means that DARLA_WINTERS can impersonate other users (including domain admins) when authenticating to *cifs* on the haystack machine. This is good news for us :thumbsup: because it means that once we have pwned DARLA_WINTERS via the password resets we can use constrained delegation to authenticate to haystack.thm.corp as a domain admin account and thereby pwn the domain controller :partying_face:

The picture below shows how we can use *Active Directory Users and Computers* on a domain controller to allow objects to delegate to services as others.

![cd3](/images/49.png)

---

## password resets

Coming back to our attack, we start to reset the passwords of the users identified as being vulnerable in our bloodhound enumeration. This can be done from our attacking machine using the *net* command.

`sudo net rpc password 'SHAWNA_BRAY' 'Password1' -U 'THM.corp'/'TABATHA_BRITT'%'<REDACTED>' -S 10.10.152.174`

We can make sure that the password has been changed by using *crackmapexec*

`sudo crackmapexec smb 10.10.152.174 -u 'SHAWNA_BRAY' -p 'Password1'`

![reset1](/images/21.png)

We now move to pwn CRUZ_HALL

`sudo net rpc password 'CRUZ_HALL' 'Password2' -U 'THM.corp'/'SHAWNA_BRAY'%'Password1' -S 10.10.152.174`

![reset2](/images/22.png)

Next we pwn our main target DARLA_WINTERS

`sudo net rpc password 'DARLA_WINTERS' 'Password3' -U 'THM.corp'/'CRUZ_HALL'%'Password2' -S 10.10.152.174`

![reset3](/images/23.png)

---

## constrained delegation abuse

Now we have pwned DARLA_WINTERS we can set about exploiting the constrained delegation associated with that account. This can again be achieved from our attacking machine. Ultimately, we obtain kerberos authentication credentials for the Administrator user who bloodhound showed to be a domain admin.

`sudo python3 getST.py -k -impersonate Administrator -spn cifs/HayStack.thm.corp/DARLA_WINTERS`

![cdeleg1](/images/24.png)

`export KRB5CCNAME=Administrator.ccache`

![cdeleg2](/images/24b.png)

![cdeleg3](/images/24c.png)

---

## getting root

We can now use *wmiexec.py* from the *impacket* suite of tools to gain an elevated shell on the haystack machine - *psexec.py* does not work - it is probably picked up by antivirus. If *psexec* does not work it is always worth trying *wmiexec* as it tends to not get picked up as much.

`sudo python3 wmiexec.py -k -no-pass Administrator@Haystack.thm.corp`

![root1](/images/25.png)

![root2](/images/26.png)

We have now pwned 💀 the reset box! 🥳

But the party is not over yet... 😈

---

## the automate user

