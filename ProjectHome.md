Pytowall's purpose is to replace fail2ban (which is not as lightweight as I was hoping for), with a centralized server and many clients telling him what ip needs to be blocked. Then, Pytowall will tell the other clients about the updated blocklist, and every client will be instantly protected against the same attackers, even before an attack strikes against that host.

The attack is discovered as soon as the informations are updated into the log files, without needing to read everytime the whole file (so, it works also with big log files since it only scans the newest lines).

It uses threads, so all the checks works in parallel, and performances are better.

No dependencies required: python itself is enough.