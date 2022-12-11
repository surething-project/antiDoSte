# antiDoSte

Denial-of-Service (DoS) attacks have a long history and there are many of them, ranging from exploits that crash individual devices to attacks that overwhelm the capacity of servers by having many clients issue a barrage of requests.
These attacks target availability and deny access of rightful users to the on-line services they need to work and play.

In this work, ANTIDOSTE – antidote for DoS, we combine the efficiency of using custom rules to detect specific attacks with the effectiveness of using Machine Learning on traffic patterns to detect previously unknown attacks.

ANTIDOSTE can detect DoS attacks, both known and unknown, and can mitigate them using virtual local area networks (VLAN), created dynamically using software-defined network (SDN) mechanisms.

Next, we explain how to install our solution

## Requirements

Ubuntu 18.04

## Mininet

First, we need to install mininet.
You can do it through this link:
http://mininet.org/download/

During the installation use the command:

```
mininet/util/install.sh -a
```

In order to install everything.

## Controller

For our prototype solution we used a Pox controller that comes pre-installed with Mininet.
The version of Pox we used was the fangtooth, so you might need to change the branch by doing, inside the pox directory:
```
git checkout fangtooth
```

Also create the directories, from outside the pox directory:
```
mkdir pox/pox/misc/aux_files
mkdir pox/pox/misc/behavior_analysis
```

## Python Environment
To run the Deep Learning model, it is required the TensorFlow python library.
However, to do so, you need a python virtual environment.
You can follow this link to install the environment and TensorFlow:
https://www.liquidweb.com/kb/how-to-install-tensorflow-on-ubuntu-18-04/


## File Location
After having everything installed you can move the files from this repository.
Every file from the SDN directory, except the CROSS_ML_controller.py, goes to the mininet directory.
The CROSS_ML_controller.py goes to the pox directory.
Finally, move the files from the Deep_Learning directory to the pox/pox/misc directory.

## Running

Start by running the controller in the pox directory:
```
python2 pox.py log.level --DEBUG misc.CROSS_ML_controller
```
Then the model, in directory pox/pox/misc:
```
python3 name_of_the_model.py
```
Finally for the mininet you can do it manually by using, inside the mininet dir:
```
sudo mn --custom mytopo.py --topo mytopo --mac --controller remote --switch ovsk
```
This will only start the test-bed, then you will need to put the traffic running by:
```
mininet> Alva python3 CROSS_server.py & #To start the server 
mininet> Jero iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.1.100 -j DROP # So the TCP packets do not get dropped by the kernel, also this is an example for a device in the 10.0.1.0/24 network
mininet> Jero ping 10.0.7.100 -c 5 #To fill the arp tables
mininet> Jero python3 name_of_the_device.py 10.0.7.100 & #Choose the type of device you want to run, example: Kio_SM.py
```
You need to do the last 3 steps of these commands for every device you want to run.

For mininet automatic running, inside the mininet dir:
```
python3 Mininet_deploy.py
```

To perform a TCP-SYN flood attack, aiming the server, you can do, inside mininet cmd:
```
mininet> [Name_of_the_attacker] python3 DoS_sc.py 10.0.7.100 # Where the name of the attacker is the  malicious device name, for example Jero.
```
