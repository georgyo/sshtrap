sshtrap
=======

A simple SSH Honey Trap, the goal is to analyze ssh bots

```
mkdir sshtrapdir; cd sshtrapdir
ssh-keygen -t rsa -b 4096 -f ./id_rsa
ssh-keygen -t dsa -b 1024 -f ./id_dsa
ssh-keygen -t ecdsa -b 521 -f ./id_ecdsa # Only avilable in newer versions of SSH
sshtrap -alsologtostderr -port 2022
```

Or to use your actual host keys

```
sudo sshtrap -alsologtostderr -port 2022 -rsa_key /etc/ssh/ssh_host_rsa_key -dsa_key /etc/ssh/ssh_host_dsa_key -ecdsa_key /etc/ssh/ssh_host_ecdsa_key
```

Much more to come.


