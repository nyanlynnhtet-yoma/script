#!/bin/bash
#backup
cp /etc/gshadow /etc/bak-gshadow && chmod 400 /etc/bak-gshadow
cp /etc/sysctl.conf /etc/sysctl-bak && chmod 400 /etc/sysctl-bak
cp /etc/login.defs /etc/loging-bak && chmod 400 /etc/loging-bak
cp /etc/ssh/ssh_config /etc/ssh/ssh-config-bak && chmod 400 /etc/ssh/ssh-config-bak
cp /etc/passwd /etc/passwd-bak && chmod 400 /etc/passwd-bak
cp /etc/modprobe.conf /etc/modprobe-bak && chmod 400 /etc/modprobe-bak



#/etc/gshadow- file permissions should be set to 0400
chmod 0400 /etc/gshadow

#The default umask for all users should be set to 077 in login.defs
sed -i '/^UMASK/ s/[0-9]\+/077/g' /etc/login.defs

#Performing source validation by reverse path should be enabled for all interfaces.
sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=1/g' /etc/sysctl.conf

#Ensure packet redirect sending is disabled.
#Sending ICMP redirects should be disabled for all interfaces. (net.ipv4.conf.default.secure_redirects = 0)
#Sending ICMP redirects should be disabled for all interfaces. (net.ipv4.conf.default.accept_redirects = 0)
#Performing source validation by reverse path should be enabled for all interfaces. (net.ipv4.conf.default.rp_filter = 1)
echo -e "net.ipv4.conf.default.secure_redirects = 0\n net.ipv4.conf.all.send_redirects = 0\n net.ipv4.conf.default.send_redirects = 0\n net.ipv4.conf.default.accept_redirects = 0\n net.ipv4.conf.default.accept_source_route = 0\n net.ipv4.conf.default.rp_filter=1\n net.ipv4.conf.all.log_martians = 1\n net.ipv4.conf.all.rp_filter = 1\n net.ipv4.conf.default.rp_filter=1\n" >> /etc/sysctl.conf



#/etc/shadow- file permissions should be set to 0400
chmod 0400 /etc/shadow

#User home directories should be mode 750 or more restrictive


#Access to the root account via su should be restricted to the 'root' group

#Appropriate ciphers should be used for SSH. (Ciphers aes128-ctr,aes192-ctr,aes256-ctr)
echo "MACs hmac-sha1,umac-64@openssh.com,hmac-ripemd160" >> /etc/ssh/ssh_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/ssh_config

#/etc/passwd- file permissions should be set to 0600
chmod 0644 /etc/passwd

#The Network File System (NFS) service should be disabled.

#Ensure SSH access is limited
echo "PermitRootLogin no" >> /etc/ssh/sshd_config 

#The portmap service should be disabled.
systemctl stop rpcbind rpcbind.socket snmpd
systemctl disable rpcbind rpcbind.socket snmpd 

#Disable the installation and use of file systems that are not required (hfsplus)
echo -e "install cramfs /bin/true \n install freevxfs /bin/true\n install jffs2 /bin/true\n install hfs /bin/true\n install hfsplus /bin/true\n install squashfs /bin/true \n install udf /bin/true\n" >> /etc/modprobe.conf 

echo 'alias net-pf-31 off' >> /etc/modprobe.conf



