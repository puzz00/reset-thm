The [reset](https://tryhackme.com/room/resetui) is a great active directory box found on [thm](https://tryhackme.com) We get to mess about in an active directory environment and there is a fun watering hole attack to be found, too... :smiling_imp: 

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
