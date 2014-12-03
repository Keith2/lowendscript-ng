#!/bin/bash

function check_install {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends -q -y $3 install $2
        print_info "$2 installed for $1"
    else
        print_warn "$2 already installed"
    fi
}

function check_remove {
    if [ -n "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge "$2"
        print_info "$2 removed"
    else
        print_warn "$2 is not installed"
    fi
}

function check_upgrade {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        print_warn "$2 not installed for $1"
    else
	DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends -q -y $3 install $2
        print_warn "$2 upgrade"
    fi
}

function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ -f /etc/lsb-release ]
    then
        die "Distribution is not supported"
    fi
    if [ ! -f /etc/debian_version ]
    then
        die "Ubuntu is not supported"
    fi

}

function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}

function get_domain_name() {
    # Getting rid of the lowest part.
    domain=${1%.*}
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    case "$lowest" in
    com|net|org|gov|edu|co)
        domain=${domain%.*}
        ;;
    esac
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    [ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_dash {
    check_install dash "dash"
    rm -f /bin/sh
    ln -s dash /bin/sh
}

function add_user {
	if [ -z `grep $USER: /etc/passwd` ]; then
		useradd -m $USER
		cat >> /etc/sudoers.d/users <<END
$USER   ALL=(ALL:ALL) ALL
END
		if [ ! -d /home/$USER/Maildir ]; then
			mkdir /home/$USER/Maildir
		fi
        if [ ! -d /home/$USER/Maildir/cur ]; then
            mkdir /home/$USER/Maildir/cur
        fi
        if [ ! -d /home/$USER/Maildir/tmp ]; then
            mkdir /home/$USER/Maildir/tmp
        fi
        if [ ! -d /home/$USER/Maildir/new ]; then
            mkdir /home/$USER/Maildir/new
        fi
		chown -R $USER:$USER /home/$USER/Maildir
		echo Set password for $USER
		passwd $USER
	fi
}

function install_dropbear {
    check_upgrade ssh "ssh" "-t wheezy-backports"
    check_remove dropbear "dropbear"
    check_install /usr/sbin/xinetd "xinetd"

    # Disable SSH
    touch /etc/ssh/sshd_not_to_be_run
    invoke-rc.d ssh stop

    if [ -z $SSH_PORT ];then
        SSH_PORT=22
        print_info "SSH port set to 22"
    else
        if [ $SSH_PORT -le 65535 ]; then
            print_info "SSH port set to $SSH_PORT"
        else
            SSH_PORT=22
            print_warn "SSH port changed to 22"
        fi
    fi
# remove deprecated file
    rm -f /etc/xinetd.d/dropbear
    # Enable ssh start. We are going to use xinetd as it is just
    # easier to configure and might be used for other things.
    cat > /etc/xinetd.d/openssh <<END
service openssh
{
    socket_type     = stream
    wait            = no
    port            = $SSH_PORT
    type            = unlisted
    flags           = $FLAGS
    user            = root
    protocol        = tcp
    server          = /usr/sbin/sshd
    server_args     = -i
    disable         = no
}
END
    invoke-rc.d xinetd restart
    ssh-keygen -f /root/.ssh/id_rsa -N "" -t rsa -b 4096
    ssh-keygen -f /root/.ssh/id_ed25519 -N "" -t ed25519
    ssh-keygen -f /etc/ssh/ssh_host_ed25519_key -N "" -t ed25519
    sed -i "/ssh_host_dsa_key/c#HostKey \/etc\/ssh\/ssh_host_dsa_key/" /etc/ssh/sshd_config
#    sed -i "/ssh_host_rsa_key/c#HostKey \/etc\/ssh\/ssh_host_rsa_key/" /etc/ssh/sshd_config
    sed -i "/ssh_host_ecdsa_key/c#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/" /etc/ssh/sshd_config
    if [ -z "`grep 'ssh_host_ed25519_key' /etc/ssh/sshd_config`" ];then
        echo "HostKey /etc/ssh/ssh_host_ed25519_key" >>/etc/ssh/sshd_config
    fi
}

function install_postfix {
    check_install postfix "postfix procmail" "-t wheezy-backports"
    cat > /etc/aliases <<END
postmaster:    $EMAIL
MAILER-DAEMON: $EMAIL
abuse:         $EMAIL
spam:          $EMAIL
hostmaster:    $EMAIL
root:          $EMAIL
nobody:        /dev/null
mail:          $EMAIL
END
    newaliases
    postconf -e "mailbox_command = /usr/bin/procmail -a "$EXTENSION" DEFAULT=/home/$USER/Maildir/"
    openssl gendh -out /etc/postfix/dh_512.pem -2 512
    openssl gendh -out /etc/postfix/dh_1024.pem -2 1024
    postconf -e "smtpd_tls_dh1024_param_file = /etc/postfix/dh_1024.pem"
    postconf -e "smtpd_tls_dh512_param_file = /etc/postfix/dh_512.pem"
    postconf -e "smtpd_tls_eecdh_grade = strong"
    postconf -e "tls_preempt_cipherlist = yes"
    postconf -e "smtpd_tls_loglevel = 1"
    postconf -e "smtp_tls_loglevel = 1"
    postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3"
    postconf -e "smtp_tls_protocols = !SSLv2, !SSLv3"
    postconf -e "smtpd_tls_received_header = yes"
    postconf -e "smtpd_tls_security_level = may"
    postconf -e "smtp_tls_security_level = may"
    postconf -e "smtpd_tls_auth_only = yes"
    postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
    service postfix reload
}

function install_percona {
    apt-key adv --keyserver keys.gnupg.net --recv-keys 1C4CBDCDCD2EFD2A
    cat > /etc/apt/sources.list.d/percona.list <<END
deb http://repo.percona.com/apt wheezy main
#deb-src http://repo.percona.com/apt wheezy main
END
    apt-get update
    # Install the Percona packages
    check_install mysqld "percona-server-server-5.5"
    check_install mysql "percona-server-client-5.5"

    # Install a low-end copy of the my.cnf to disable InnoDB, and then delete
    # all the related files.
    invoke-rc.d mysql stop
    rm -f /var/lib/mysql/ib*
    cat > /etc/mysql/conf.d/lowendbox.cnf <<END
[mysqld]
key_buffer = 8M
query_cache_size = 0
ignore_builtin_innodb
default_storage_engine=MyISAM
END
    invoke-rc.d mysql start

	if [ ! -e ~/.my.cnf ]; then
    	# Generating a new password for the root user.
    	passwd=`get_password root@mysql`
    	mysqladmin password "$passwd"
    	cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
	fi
    chmod 600 ~/.my.cnf
}

function install_nginx {
    wget -O - http://nginx.org/keys/nginx_signing.key | apt-key add -
    cat > /etc/apt/sources.list.d/nginx.list <<END
deb http://nginx.org/packages/debian/ wheezy nginx
#deb-src http://nginx.org/packages/debian/ wheezy nginx
END
    apt-get update

    check_install nginx "nginx"

    if [ ! -d /etc/nginx/ssl_keys ]; then
        mkdir /etc/nginx/ssl_keys
    fi
    if [ ! -e /etc/nginx/ssl_keys/dhparam-2048.pem ]; then
        openssl dhparam -out /etc/nginx/ssl_keys/dhparam-2048.pem 2048
    fi

# Create a ssl default ssl certificate.
# This can be reused instead of creating a creating a self signed certificate.
    if [ ! -e /etc/nginx/ssl_keys/default.pem ]; then
	cat > /etc/nginx/ssl_keys/default.conf <<END
[req]
distinguished_name  = req_distinguished_name

[ req_distinguished_name ]
countryName         = Country Name (2 letter code)
countryName_default     = XX
countryName_min         = 2
countryName_max         = 2

commonName          = Common Name (eg, YOUR name)
commonName_default  = Default CA
commonName_max          = 64
END
	openssl genrsa -passout pass:password -des3 -out /etc/nginx/ssl_keys/default.key.secure 4096
	openssl req -passin pass:password -new -x509 -key /etc/nginx/ssl_keys/default.key.secure -out /etc/nginx/ssl_keys/default.pem -days 3650 -config /etc/nginx/ssl_keys/default.conf -batch
	openssl rsa -passin pass:password -in /etc/nginx/ssl_keys/default.key.secure -out /etc/nginx/ssl_keys/default.key

	#openssl ecparam -out /etc/nginx/ssl_keys/default.ec.key -name secp521r1 -genkey
	#openssl req -new -key /etc/nginx/ssl_keys/default.ec.key -x509 -nodes -days 3650 -out /etc/nginx/ssl_keys/default.ec.crt -config /etc/nginx/ssl_keys/default.ec.conf -batch
    fi

    cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes $CPUCORES;
pid /run/nginx.pid;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	server_names_hash_bucket_size 64;
	ignore_invalid_headers on;
	server_tokens off;
	log_format  main  '\$remote_addr \$host \$server_port \$remote_user [\$time_local] "\$request" '
               '\$status \$body_bytes_sent "\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
	upstream php {
		server unix:/var/run/php5-fpm.sock;
	}

	# server_name_in_redirect off;

	include mime.types;
	default_type application/octet-stream;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log main;
	error_log /var/log/nginx/error.log error;

	##
	# Gzip Settings
	##

	gzip on;
	gzip_disable "msie6";
	gzip_min_length 1400;
	gzip_vary on;
	gzip_proxied any;
	gzip_comp_level 6;
	gzip_buffers 16 8k;
	gzip_http_version 1.1;
	gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

	ssl_certificate ssl_keys/default.pem;
	ssl_certificate_key ssl_keys/default.key;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
	ssl_dhparam ssl_keys/dhparam-2048.pem;
	ssl_session_timeout 5m;
	ssl_session_cache shared:SSL:50m;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:HIGH:!aNULL;
	ssl_prefer_server_ciphers on;

        #fastcgi_cache_path /home/nginx-cache levels=1:2 keys_zone=CACHE:100m inactive=60m;
        #fastcgi_cache_key "$scheme$request_method$host$request_uri";

        client_max_body_size 8m;

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

END

# Remove deprecated file
    rm -f /etc/nginx/conf.d/lowendbox.conf

# Make sure sites-available & sites enabled exist
# Should only be needed when installing a cpu optimised nginx from my own repository.
	if [ ! -d /etc/nginx/sites-available ]; then
		mkdir /etc/nginx/sites-available
	fi
	if [ ! -d /etc/nginx/sites-enabled ]; then
		mkdir /etc/nginx/sites-enabled
	fi

    cat > /etc/nginx/sites-available/default <<END
server {
END
    if [ "$INTERFACE" = "all" ]; then
        cat >> /etc/nginx/sites-available/default <<END
    listen 80 default_server; ## listen for ipv4
    listen 443 default_server ssl; ## listen for ipv4
    listen [::]:80 default_server ipv6only=on; ## listen for ipv6
    listen [::]:443 default_server ipv6only=on ssl; ## listen for ipv6
END
    else
        if [ "$INTERFACE" = "ipv6" ]; then
            cat >> /etc/nginx/sites-available/default <<END
    listen [::]:80 default_server; ## listen for ipv6
    listen [::]:443 default_server ipv6only=on ssl; ## listen for ipv6
END
        else
            cat >> /etc/nginx/sites-available/default <<END
    listen 80 default_server; ## listen for ipv4
    listen 443 default_server ssl; ## listen for ipv4
END
        fi
    fi
    cat >> /etc/nginx/sites-available/default <<END
    server_name  _;
    access_log  /var/log/nginx/default.log main;
    ssl_ciphers "ALL:!aNULL:!RC4";
    return 444;
}
END
	cat > /etc/nginx/standard.conf <<END
location = /favicon.ico {
	return 204;
	log_not_found off;
	access_log off;
}

location = /robots.txt {
	log_not_found off;
	access_log off;
}

# Make sure files with the following extensions do not get loaded by nginx because nginx would display the source code, and these files can contain PASSWORDS!
location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\.php)?|xtmpl)$|^(\..*|Entries.*|Repository|Root|Tag|Template)$|\.php_
{
	return 444;
}

# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac).
location ~ /\. {
	return 444;
	access_log off;
	log_not_found off;
	}

location ~*  \.(jpg|jpeg|png|gif|css|js|ico)$ {
	expires max;
	log_not_found off;
}
END
    cat > /etc/nginx/nophp.conf <<END
location ~* \.php\$ {
	return 444;
}
END
    cat > /etc/nginx/nocgi.conf <<END
location ~* \\.(pl|cgi|py|sh|lua)\$ {
	return 444;
}
END
    cat > /etc/nginx/disallow.conf <<END
location ~* (roundcube|webdav|smtp|http\\:|soap|w00tw00t) {
	return 444;
}
if (\$http_user_agent ~* "(Morfeus|larbin|ZmEu|Toata|Huawei|talktalk)" ) {
	return 444;
}
END
#   delete deprecated file
    rm -f /etc/nginx/disallow-agent.conf

    invoke-rc.d nginx restart
    chown www-data:adm /var/log/nginx/*
    sed -i "s/rotate 52/rotate 1/" /etc/logrotate.d/nginx
}

function install_nginx-upstream {
    wget -O - http://nginx.org/keys/nginx_signing.key | apt-key add -
    cat > /etc/apt/sources.list.d/nginx.list <<END
deb http://nginx.org/packages/debian/ wheezy nginx
#deb-src http://nginx.org/packages/debian/ wheezy nginx
END
    apt-get update
    apt-get -y remove nginx nginx-full nginx-common
    apt-get install nginx
    sed -i "s/rotate 52/rotate 1/" /etc/logrotate.d/nginx
}

function install_php {
    check_install php5-fpm "php5-fpm php5-cli php5-mysqlnd php5-cgi php5-gd php5-curl php5-xcache"
    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php$ {
	include /etc/nginx/fastcgi_params;
	fastcgi_index index.php;
	fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
	if (-f \$request_filename) {
		fastcgi_pass php;
	}
}
END
    sed -i "/pm =/cpm = ondemand" /etc/php5/fpm/pool.d/www.conf
    if [ "$MEMORY" = "low" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 1" /etc/php5/fpm/pool.d/www.conf
	elif [ "$MEMORY" = "64" ]; then
		sed -i "/pm.max_children =/cpm.max_children = 2" /etc/php5/fpm/pool.d/www.conf
	elif [ "$MEMORY" = "96" ]; then
       	sed -i "/pm.max_children =/cpm.max_children = 3" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "128" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 4" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "192" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 6" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "256" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 8" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "384" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 12" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "512" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 16" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "1028" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 32" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "2048" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 64" /etc/php5/fpm/pool.d/www.conf
    fi
    sed -i "/pm.max_requests =/cpm.max_requests = 500" /etc/php5/fpm/pool.d/www.conf
    sed -i "/pm.status_path =/cpm.status_path = \/status" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen =/clisten = /var/run/php5-fpm.sock" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen.owner =/clisten.owner = www-data" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen.group =/clisten.group = www-data" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen.mode =/clisten.mode = 0666" /etc/php5/fpm/pool.d/www.conf
    service php5-fpm restart
    if [ -f /etc/init.d/php-cgi ];then
        service php-cgi stop
        update-rc.d php-cgi remove
        rm /etc/init.d/php-cgi
        service nginx restart
        print_info "/etc/init.d/php-cgi removed"
    fi
}

function install_cgi {
    check_install fcgiwrap "fcgiwrap"
    cat > /etc/nginx/fcgiwrap.conf <<END
location ~ (\.cgi|\.py|\.sh|\.pl|\.lua)$ {
    gzip off;
    root  /var/www/\$server_name;
    autoindex on;
    fastcgi_pass  unix:/var/run/fcgiwrap.socket;
    include /etc/nginx/fastcgi_params;
    fastcgi_param  DOCUMENT_ROOT      /var/www/\$server_name;
    fastcgi_param SCRIPT_FILENAME  /var/www/\$server_name\$fastcgi_script_name;
}
END
}

function install_domain {
    if [ -z "$2" ]
    then
        die "Usage: `basename $0` domain <hostname>"
    fi
	if [ "$3" = "redo" ]; then
		rm /etc/nginx/sites-available/$2.conf /etc/nginx/sites-enabled/$2.conf /var/www/$2/index.html
		if [ -e /var/www/$2/index.sh ]; then
			rm /var/www/$2/index.sh
		fi
	fi
    if [ ! -d /var/www ]; then
        mkdir /var/www
        chown root:root /var/www
    fi

    if [ ! -d /var/www/$2 ]; then
		mkdir /var/www/$2
	fi
	chown www-data:www-data /var/www/$2
    cat > "/var/www/$2/index.html" <<END
<html><head>
<title>$2</title>
<meta name='description' content=$2>
<meta name='keywords' content=$2>
<meta http-equiv='Content-type' content='text/html;charset=UTF-8'>
<meta name='ROBOTS' content='INDEX, FOLLOW'>
</head><body>
<h1>It works!</h1>
<p>This is the default web page for $2</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>
END
    cat > "/var/www/$2/robots.txt" <<END
User-agent: *
Disallow: /
END
# Setting up Nginx mapping
cat > "/etc/nginx/sites-available/$2.conf" <<END
server {
	listen 80;
END
	if [ "$FLAGS" = "ipv6" ]; then
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
	listen [::]:80;
END
	fi
    cat >> "/etc/nginx/sites-available/$2.conf" <<END
	server_name  www.$2;
        return 301 http://$2\$request_uri;
}

server {
	listen 80;
END
    if [ "$FLAGS" = "ipv6" ]; then
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
	listen [::]:80;
	server_name $2;
END
	else
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
	server_name $2;
END
    cat >> "/etc/nginx/sites-available/$2.conf" <<END
	access_log /var/log/nginx/$2.log main;
	include standard.conf;
#	include fastcgi_php;
 	include nophp.conf;
#	include fcgiwrap.conf;
	include nocgi.conf;
	include disallow.conf;
END

    cat >> "/etc/nginx/sites-available/$2.conf" <<END
	root /var/www/$2;
	index index.html;
}
END
    cat > "/etc/nginx/myips.conf" <<END
allow 127.0.0.1;
#deny all; # Used to restrict access to yourself for non-public areas of websites
# Uncomment the above line, comment the following line and add your allowed ip subnets after allow 127.0.0.1
allow all;
END

    ln -s /etc/nginx/sites-available/$2.conf /etc/nginx/sites-enabled/$2.conf
    invoke-rc.d nginx reload
fi
}
function install_iptables {

    check_install iptables "iptables"

    if [ -z "$1" ]
    then
        die "Usage: `basename $0` iptables <ssh-port-#>"
    fi
    KERNEL=`uname -r`
    if [ ! -d /lib/modules/$KERNEL ]; then
        mkdir /lib/modules/$KERNEL
        depmod
    fi
    # Create startup rules
    cat > /etc/init.d/iptables <<END
#! /bin/sh

#This is an Ubuntu adapted iptables script from gentoo
#(http://www.gentoo.org) which was originally distributed
#under the terms of the GNU General Public License v2
#and was Copyrighted 1999-2004 by the Gentoo Foundation
#
#This adapted version was intended for and ad-hoc personal
#situation and as such no warranty is provided.

### BEGIN INIT INFO
# Provides:          iptables
# Required-Start:    \$local_fs \$remote_fs \$network \$syslog
# Required-Stop:     \$local_fs \$remote_fs \$network \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the iptables firewall
### END INIT INFO

. /lib/lsb/init-functions


IPTABLES_SAVE="/etc/default/iptables-rules"
SAVE_RESTORE_OPTIONS="-c"


checkrules() {
    if [ ! -f \${IPTABLES_SAVE} ]
    then
        echo "Not starting iptables. First create some rules then run"
        echo "\"/etc/init.d/iptables save\""
        return 1
    fi
}

save() {
    /sbin/iptables-save \${SAVE_RESTORE_OPTIONS} > \${IPTABLES_SAVE}
    return \$?
}

start(){
    checkrules || return 1
    /sbin/iptables-restore \${SAVE_RESTORE_OPTIONS} < \${IPTABLES_SAVE}
    return \$?
}


case "\$1" in
    save)
        echo -n "Saving iptables state..."
        save
        if [ \$? -eq 0 ] ; then
            echo " ok"
        else
            echo " error !"
        fi
    ;;

    start)
        log_begin_msg "Loading iptables state and starting firewall..."
        start
        log_end_msg \$?
    ;;
    stop)
        log_begin_msg "Stopping firewall..."
        for a in \`cat /proc/net/ip_tables_names\`; do
            /sbin/iptables -F -t \$a
            /sbin/iptables -X -t \$a

            if [ \$a == nat ]; then
                /sbin/iptables -t nat -P PREROUTING ACCEPT
                /sbin/iptables -t nat -P POSTROUTING ACCEPT
                /sbin/iptables -t nat -P OUTPUT ACCEPT
            elif [ \$a == mangle ]; then
                /sbin/iptables -t mangle -P PREROUTING ACCEPT
                /sbin/iptables -t mangle -P INPUT ACCEPT
                /sbin/iptables -t mangle -P FORWARD ACCEPT
                /sbin/iptables -t mangle -P OUTPUT ACCEPT
                /sbin/iptables -t mangle -P POSTROUTING ACCEPT
            elif [ \$a == filter ]; then
                /sbin/iptables -t filter -P INPUT ACCEPT
                /sbin/iptables -t filter -P FORWARD ACCEPT
                /sbin/iptables -t filter -P OUTPUT ACCEPT
            fi
        done
        log_end_msg 0
    ;;

    restart)
        log_begin_msg "Restarting firewall..."
        for a in \`cat /proc/net/ip_tables_names\`; do
            /sbin/iptables -F -t \$a
            /sbin/iptables -X -t \$a
        done;
        start
        log_end_msg \$?
    ;;

    *)
        echo "Usage: /etc/init.d/iptables {start|stop|restart|save}" >&2
        exit 1
        ;;
esac

exit 0
END
    chmod +x /etc/init.d/iptables

    # Flush any existing iptables
    /sbin/iptables -v -F

    # http://articles.slicehost.com/2010/4/30/ubuntu-lucid-setup-part-1

    #  Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
    /sbin/iptables -v -A INPUT -i lo -j ACCEPT
    /sbin/iptables -v -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

    #  Accepts all established inbound connections
    /sbin/iptables -v -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    #  Allows all outbound traffic
    #  You can modify this to only allow certain traffic
    /sbin/iptables -v -A OUTPUT -j ACCEPT

    # Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
    /sbin/iptables -v -A INPUT -p tcp --dport 80 -j ACCEPT
    /sbin/iptables -v -A INPUT -p tcp --dport 443 -j ACCEPT

    # IF YOU USE INCOMMING MAIL UN-COMMENT THESE!!!

    # Allows POP (and SSL-POP)
    #/sbin/iptables -v -A INPUT -p tcp --dport 110 -j ACCEPT
    #/sbin/iptables -v -A INPUT -p tcp --dport 995 -j ACCEPT

    # SMTP (and SSMTP)
    #/sbin/iptables -v -A INPUT -p tcp --dport 25 -j ACCEPT
    #/sbin/iptables -v -A INPUT -p tcp --dport 465 -j ACCEPT

    # IMAP (and IMAPS)
    #/sbin/iptables -v -A INPUT -p tcp --dport 143 -j ACCEPT
    #/sbin/iptables -v -A INPUT -p tcp --dport 993 -j ACCEPT

    #  Allows SSH connections (only 3 attempts by an IP every 2 minutes, drop the rest to prevent SSH attacks)
    /sbin/iptables -v -A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --set --name DEFAULT --rsource
    /sbin/iptables -v -A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --update --seconds 120 --hitcount 3 --name DEFAULT --rsource -j DROP
    /sbin/iptables -v -A INPUT -p tcp -m state --state NEW --dport $1 -j ACCEPT

    # Allow ping
    /sbin/iptables -v -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

    # log iptables denied calls
    /sbin/iptables -v -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

    # Reject all other inbound - default deny unless explicitly allowed policy
    /sbin/iptables -v -A INPUT -j REJECT
    /sbin/iptables -v -A FORWARD -j REJECT

    /etc/init.d/iptables save
    update-rc.d iptables defaults
}

function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd "inetutils-syslogd"
    invoke-rc.d inetutils-syslogd stop

    for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
    do
        [ -f "$file" ] && rm -f "$file"
    done
    for dir in fsck news
    do
        [ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
    done

    cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.*                  -/var/log/cron
mail.*                  -/var/log/mail
END

    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
   rotate 4
   weekly
   missingok
   notifempty
   compress
   sharedscripts
   postrotate
   /etc/init.d/inetutils-syslogd reload >/dev/null
   endscript
}
END

    invoke-rc.d inetutils-syslogd start
}

function install_wordpress {
    check_install wget "wget"
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

    # Downloading the WordPress' latest and greatest distribution.
    mkdir /tmp/wordpress.$$
    wget -O - http://wordpress.org/latest.tar.gz | \
        tar zxf - -C /tmp/wordpress.$$
    if [ ! -d /var/www ]; then
        mkdir /var/www
    fi
    mv /tmp/wordpress.$$/wordpress "/var/www/$1"
    rm -rf /tmp/wordpress.$$
    chown root:root -R "/var/www/$1"

    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    # MySQL userid cannot be more than 15 characters long
    userid="${userid:0:15}"
    passwd=`get_password "$userid@mysql"`
    cp "/var/www/$1/wp-config-sample.php" "/var/www/$1/wp-config.php"
    sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
        "/var/www/$1/wp-config.php"
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql
    # Setting up Nginx mapping
    cat > "/etc/nginx/sites-available/$1.conf" <<END
server {
	listen 80;
	listen [::]:80;
	server_name $1;
	root /var/www/$1;
	access_log /var/log/nginx/$1.log main buffer=16k;
	index index.php;
	include standard.conf;
	include fastcgi_php;
	include nocgi.conf;
	include disallow.conf;
END
	cat >> "/etc/nginx/sites-available/$1.conf" <<END

    location / {
        try_files \$uri \$uri/ /index.php;
    }

END
	if [ -e /etc/nginx/myips.conf ]; then
    	    cat >> "/etc/nginx/sites-available/$1.conf" <<END
    location /wp-admin {
        include myips.conf;
        try_files \$uri \$uri/ /index.php;
    }

END
	fi
	cat >> "/etc/nginx/sites-available/$1.conf" <<END
    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        #NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass php;
    }
}
END
    ln -s /etc/nginx/sites-available/$1.conf /etc/nginx/sites-enabled/$1.conf
    service nginx force-reload
}

function install_friendica {
	if [ -z "$2" ]; 	then
		die "Usage: `basename $0` friendica <hostname>"
	fi
	if [ -d /var/www/$2 -a ! "$3" = "redo" ]; then
		die "$2 already exists"
	fi
	check_install "friendica dependencies" "git php5-imap php5-mcrypt"
	if [ ! -d /var/www ]; then
		mkdir /var/www
		chown www-data:www-data /var/www
	fi
	cd /var/www
	if [ -d friendica ]; then
		rm -r friendica #Delete previous clone, which may have errors
	fi
	if [ ! "$3" = "redo" ]; then
		git clone https://github.com/friendica/friendica.git
		mv friendica $2
		chown -R www-data:www-data $2
		cd $2
		git clone https://github.com/friendica/friendica-addons.git
		mv friendica-addons addon
		chown www-data:www-data addon view/smarty3
	fi
	cd /var/www/$2
    cat > "/etc/nginx/sites-available/$2.conf" <<END
server {
        listen 80;
END
    if [ "$FLAGS" = "ipv6" -o "$FLAGS" = "all" ]; then
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
        listen [::]:80;
END
    fi
    cat >> "/etc/nginx/sites-available/$2.conf" <<END
        server_name $2;
        access_log off;
        return 301 https://$2/$request_uri;
}
END
    cat >> "/etc/nginx/sites-available/$2.conf" <<END
server {
	listen 443 ssl spdy;
END
    if [ "$FLAGS" = "ipv6" -o "$FLAGS" = "all" ]; then
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
	listen [::]:443 ssl spdy;
END
    fi
    cat >> "/etc/nginx/sites-available/$2.conf" <<END
	server_name $2;
	access_log /var/log/nginx/$2.log main buffer=16k;
	root /var/www/$2;

    ssl_certificate ssl_keys/default.pem;
    ssl_certificate_key ssl_keys/default.key;
#	ssl_certificate ssl_keys/$2.pem;
#	ssl_certificate_key ssl_keys/$2.key;

	location = /favicon.ico {
		expires max;
		log_not_found off;
		access_log off;
		return 204;
	}

	location = /robots.txt {
		log_not_found off;
		access_log off;
	}

	location ~ /\.(ht|git) {
		return 444;
		access_log off;
		log_not_found off;
	}

	location ~ \.log$ {
		return 444;
		access_log off;
		log_not_found off;
	}

	location ~ \.php$ {
		fastcgi_split_path_info ^(.+\.php)(/.+)$;
		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME \$request_filename;
		fastcgi_param HTTPS on;
		fastcgi_index index.php;
		fastcgi_pass php;
		try_files \$uri \$uri/ =404;
	}

	location / {
		index index.php;
		if (!-f \$request_filename) {
			rewrite ^/(.+)\$ /index.php?q=\$1 last;
		}
		try_files \$uri \$uri/ =404;
	}
}
END
	cat > "/var/www/$2/robots.txt" <<END
User-agent: *
Disallow: /
END
        if [ !  "$3" = "redo" ]; then
                cat >> "/etc/crontab" <<END
50 7 * * * root cd /var/www/$2;git pull;cd addon;git pull
*/10 * * * *   www-data  cd /var/www/$2; /usr/bin/php include/poller.php
END
        fi
	ln -s /etc/nginx/sites-available/$2.conf /etc/nginx/sites-enabled/$2.conf
	service nginx force-reload
	cd /var/www/$2
	cp htconfig.php .htconfig.php
	echo -n "Enter admin email: "
	read -e EMAIL
	sed -i "/\['admin_email'\]/c\$a->config['admin_email'] = '$EMAIL';" .htconfig.php
	sed -i "/\['sitename'\]/c\$a->config['sitename'] = '$2';" .htconfig.php
	dbname=`echo $2 | tr . _`
	echo database is $dbname
	echo $userid;
	# MySQL userid cannot be more than 15 characters long
	userid="${dbname:0:15}"
	echo $userid;
	passwd=`get_password "$userid@mysql"`
	mysqladmin create "$dbname"
	echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | mysql
	sed -i "/\$db_host =/c\$db_host = 'localhost';" .htconfig.php
	sed -i "/\$db_user =/c\$db_user = '$userid';" .htconfig.php
	sed -i "/\$db_pass =/c\$db_pass = '$passwd';" .htconfig.php
	sed -i "/\$db_data =/c\$db_data = '$dbname';" .htconfig.php
	mysql $dbname < ./database.sql
}

function install_red {
	if [ ! -f /etc/nginx/ssl_keys/$2.crt -o ! -f /etc/nginx/ssl_keys/$2.key ]; then
		die "No signed ssl cert at /etc/nginx/ssl_keys/$2.crt or /etc/nginx/ssl_keys/$2.key for $2"
	fi
        if [ -z "$2" ];         then
                die "Usage: `basename $0` red <hostname>"
        fi
        if [ -d /var/www/$2 -a ! "$3" = "redo" ]; then
                die "$2 already exists"
        fi
        check_install "red dependencies" "git php5-mcrypt"
        if [ ! -d /var/www ]; then
                mkdir /var/www
                chown www-data:www-data /var/www
        fi
        cd /var/www
        if [ -d red ]; then
                rm -r red #Delete previous clone, which may have errors
        fi
        if [ ! "$3" = "redo" ]; then
                git clone https://github.com/friendica/red.git
                mv red $2
                chown -R www-data:www-data $2
                cd $2
                git clone https://github.com/friendica/red-addons.git
                mv red-addons addon
	        mkdir -p "store/[data]/smarty3"
	        chmod -R 777 store
        fi
        cd /var/www/$2
    cat > "/etc/nginx/sites-available/$2.conf" <<END
server {
        listen 80;
END
	if [ "$FLAGS" = "ipv6" -o "$FLAGS" = "all" ]; then
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
        listen [::]:80;
END
        fi
    cat >> "/etc/nginx/sites-available/$2.conf" <<END
        server_name $2;
        access_log off;
	return 301 https://$2/$request_uri;
}

server {
        listen 443 ssl spdy;
END
	if [ "$FLAGS" = "ipv6" -o "$FLAGS" = "all" ]; then
        cat >> "/etc/nginx/sites-available/$2.conf" <<END
        listen [::]:443 ssl spdy;
END
	fi
	cat >> "/etc/nginx/sites-available/$2.conf" <<END
        server_name $2;
        access_log /var/log/nginx/$2.log main buffer=16k;
        charset utf-8;
        root /var/www/$2;

        ssl_certificate ssl_keys/$2.crt;
        ssl_certificate_key ssl_keys/$2.key;

        client_max_body_size 20m;
        client_body_buffer_size 128k;

        location = /favicon.ico {
                expires max;
                log_not_found off;
                access_log off;
                return 204;
        }

        location = /robots.txt {
                log_not_found off;
                access_log off;
        }

        # rewrite to front controller as default rule
        location / {
                rewrite ^/(.*) /index.php?q=\$uri&\$args last;
        }

        # make sure webfinger and other well known services aren't blocked
        # by denying dot files and rewrite request to the front controller
        location ^~ /.well-known/ {
                allow all;
                rewrite ^/(.*) /index.php?q=\$uri&\$args last;
        }

        # statically serve these file types when possible
        # otherwise fall back to front controller
        # allow browser to cache them
        # added .htm for advanced source code editor library
        location ~* \.(jpg|jpeg|gif|png|ico|css|js|htm|html|ttf|woff|svg)$ {
                expires 30d;
                try_files \$uri /index.php?q=\$uri&\$args;
        }

        # block these file types
        location ~* \.(tpl|md|tgz|log|out)$ {
                deny all;
        }

        location ~* \.php$ {
                # Zero-day exploit defense.
                # http://forum.nginx.org/read.php?2,88845,page=3
                # Won't work properly (404 error) if the file is not stored on this
                # server, which is entirely possible with php-fpm/php-fcgi.
                # Comment the 'try_files' line out if you set up php-fpm/php-fcgi on
                # another machine. And then cross your fingers that you won't get hacked.
                try_files \$uri =404;

                # NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                include fastcgi_params;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME \$request_filename;
                fastcgi_pass php;
                fastcgi_read_timeout 300;
#                fastcgi_cache CACHE;
#                fastcgi_cache_valid 200 302 10m;
#                fastcgi_cache_valid 301 1h;
        }

        # deny access to all dot files
        location ~ /\. {
                deny all;
        }

        #deny access to store
        location ~ /store {
                deny all;
        }
}
END
        cat > "/var/www/$2/robots.txt" <<END
User-agent: *
Disallow: /
END
        if [ !  "$3" = "redo" ]; then
                cat >> "/etc/crontab" <<END
50 7 * * * root cd /var/www/$2;git pull;cd addon;git pull
*/10 * * * *   www-data  cd /var/www/$2; /usr/bin/php include/poller.php
END
        fi
        ln -s /etc/nginx/sites-available/$2.conf /etc/nginx/sites-enabled/$2.conf
        service nginx force-reload
        cd /var/www/$2
        cp view/en/htconfig.tpl .htconfig.php
        echo -n "Enter admin email: "
        read -e EMAIL
        sed -i "/\['admin_email'\]/c\$a->config['system']['admin_email'] = '$EMAIL';" .htconfig.php
        sed -i "/\['baseurl'\]/c\$a->config['system']['baseurl'] = 'https://$2';" .htconfig.php
        sed -i "/\['location_hash'\]/c\$a->config['system']['location_hash'] = '`cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 64 | head -n 1`';" .htconfig.php
        sed -i "/\['php_path'\]/c\$a->config['system']['php_path'] = '/usr/bin/php';" .htconfig.php
        dbname=`echo $2 | tr . _`
        echo database is $dbname
        echo $userid;
        # MySQL userid cannot be more than 15 characters long
        userid="${dbname:0:15}"
        echo $userid;
        passwd=`get_password "$userid@mysql"`
        mysqladmin create "$dbname"
        echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | mysql
        sed -i "/\$db_host =/c\$db_host = 'localhost';" .htconfig.php
        sed -i "/\$db_user =/c\$db_user = '$userid';" .htconfig.php
        sed -i "/\$db_port =/c\$db_port = '0';" .htconfig.php
        sed -i "/\$db_pass =/c\$db_pass = '$passwd';" .htconfig.php
        sed -i "/\$db_data =/c\$db_data = '$dbname';" .htconfig.php
        sed -i "/\$db_type =/c\$db_type = '0'; // an integer. 0 or unset for mysql, 1 for postgres" .htconfig.php
        sed -i "/\$default_timezone =/c\$default_timezone = 'America/Los_Angeles';" .htconfig.php
        mysql $dbname < install/schema_mysql.sql
}

function install_yourls {
    if [ -z "$2" ]; then
        die "Usage: `basename $0` yourls <hostname>"
    fi
    if [ -d /var/www/$2 -a ! "$3" = "redo" ]; then
        die "$2 already exists"
    fi
    #check_install "yourls dependencies" "git php5-imap php5-mcrypt"
    if [ ! -d /var/www ]; then
        mkdir /var/www
    fi
    cd /var/www
}

function install_imap {
    if [ -z "$2" ]; then
        die "Usage: `basename $0` imap <username> <hostname>"
    fi
    if [ -d /var/www/$3 -a ! "$4" = "redo" ]; then
        die "$3 already exists"
    fi
    check_install imap "postfix dovecot-imapd squirrelmail procmail php5-imap"
	if [ -z "`grep $2: /etc/passwd`" ]; then
        useradd -g users -m $2
		echo creating password for $2
		passwd $2
    fi
    if [ ! -d /home/$2/Maildir ]; then
        mkdir /home/$2/Maildir
        mkdir /home/$2/Maildir/cur
        mkdir /home/$2/Maildir/tmp
        mkdir /home/$2/Maildir/new
		chown -R $2:users /home/$2/Maildir
    fi
    sed -i "/protocols = imap/cprotocols = imap" /etc/dovecot/dovecot.conf
    sed -i "/#listen =/clisten = 127.0.0.1" /etc/dovecot/dovecot.conf
    sed -i "/disable_plaintext_auth =/cdisable_plaintext_auth = no" /etc/dovecot/dovecot.conf
    sed -i "/login_processes_count =/clogin_processes_count = 1" /etc/dovecot/dovecot.conf
	service dovecot force-reload
	ln -s /usr/share/squirrelmail /var/www/$3

    cat >> "/etc/nginx/sites-available/$2.conf" <<END
server {
    listen 80;
    server_name $3;
	access_log /var/log/nginx/$3.log;
    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass php;
	}
	include myips.conf;
    root   /var/www/$3/;
    index  src/index.php;
	include standard.conf;
	location ~* ^/(.+\.(html|xml|txt))$ {
		expires max;
		log_not_found off;
	}
}
END
    ln -s /etc/nginx/sites-available/$3.conf /etc/nginx/sites-enabled/$3.conf
}

function install_statusnet {
    if [ -z "$2" ]; then
        die "Usage: `basename $0` statusnet <hostname>"
    fi
    if [ -d /var/www/$2 -a ! "$3" = "redo" ]; then
        die "$2 already exists"
    fi
    check_install "statusnet dependencies" "git php5-imap php5-mcrypt"
    if [ ! -d /var/www ]; then
        mkdir /var/www
    fi
    cd /var/www
}

function print_info {
    echo -n -e '\e[1;36m'
    echo -n $1
    echo -e '\e[0m'
}

function print_warn {
    echo -n -e '\e[1;33m'
    echo -n $1
    echo -e '\e[0m'
}

function remove_unneeded {
    # Some Debian have portmap installed. We don't need that.
    if [ "$OPENVZ" != 'gnome' ]; then
        check_remove /sbin/portmap portmap
    fi
    # Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
    # which might make some low-end VPS inoperatable. We will do this even
    # before running apt-get update.
    check_remove /usr/sbin/rsyslogd rsyslog

    # Other packages that seem to be pretty common in standard OpenVZ
    # templates.
    if [ ! "SERVER" = "apache" ]; then
	check_remove /usr/sbin/apache2 'apache2*'
    fi
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd
    apt-get -q -y purge smbfs libapr1

    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        invoke-rc.d sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
# Remove deprecated file
    rm -f /etc/apt/sources.list.d/dotdeb.list
}

function update_upgrade {
    # Run through the apt-get update/upgrade first. This should be done before
    # we try to install any package

    cat > /etc/apt/sources.list.d/backports.list <<END
deb http://ftp.debian.org/debian/ wheezy-backports main
#deb-src http://ftp.debian.org/debian/ wheezy-backports main
END
    apt-get -q -y update
    if [ "$OPENVZ" = 'yes' ]; then
        if [ -z "`grep 'ulimit -s 256' /etc/init.d/rc`" ];then
           sed -i "s/export PATH/export PATH\\nulimit -s 256/" /etc/init.d/rc
        fi
        if [ ! -f /etc/security/limits.d/stack.conf ]; then
            cat > /etc/security/limits.d/stack.conf <<END
root            -       stack           256
*               -       stack           256
END
        fi
    fi
	check_install sudo "sudo"
	add_user
    check_install dialog "dialog"
    check_install locales "locales"
    dpkg-reconfigure locales
    apt-get -q -y upgrade
    check_install tzdata "tzdata"
    dpkg-reconfigure tzdata
    install_dash
    install_syslogd
    install_dropbear
    echo -n "To change root password press y then [ENTER]: "
    read -e reply
    if [ "$reply" = "y" ]; then
        passwd
    fi
}

#                                      OPTIONAL

#Custom commands go here, mine are included as examples delete as required
function custom {
    check_install keith "rsync autossh apticron dnsutils mc python logrotate apt-utils ioping"
    if [ "$OPENVZ" != 'gnome' ]; then
        check_remove fancontrol fancontrol
        check_remove dbus-daemon dbus
    fi
    check_remove saslauthd sasl2-bin
    if [ -n '`grep "# set softwrap" /etc/nanorc`' ];then
        sed -i "s/# set softwrap/set softwrap/" /etc/nanorc
        print_info "set softwrap in /etc/nanorc"
    fi
#    if [ -n '`grep "# set tabsize 8" /etc/nanorc`' ];then
#        sed -i "s/# set tabsize 8/set tabsize 4/" /etc/nanorc
#        print_info "set tabsize 4 in /etc/nanorc"
#    fi
    sed -i "/Port 22/c\ \ \ Port 13022" /etc/ssh/ssh_config
    sed -i "/HashKnownHosts/c\ \ \ HashKnownHosts no" /etc/ssh/ssh_config
    if [ -z "`grep 'ControlMaster' /etc/ssh/ssh_config`" ];then
        echo "   ControlMaster auto" >>/etc/ssh/ssh_config
    fi
    if [ -z "`grep 'ControlPath' /etc/ssh/ssh_config`" ];then
        echo "   ControlPath ~/.ssh/master-%r@%h:%p" >>/etc/ssh/ssh_config
    fi
    if [ -z "`grep 'MAILTO=' /etc/crontab`" ];then
        sed -i "s/SHELL=\/bin\/sh/SHELL=\/bin\/sh\\nMAILTO=root/" /etc/crontab
        print_info "MAILTO=root now in /etc/crontab"
    fi
    sed -i "s/weekly/daily/" /etc/logrotate.conf
    sed -i "s/rotate 4/rotate 1/" /etc/logrotate.conf
    chown www-data:adm /var/log/nginx/*.log
    service nginx restart
    cat > /usr/local/bin/bootmail.py <<END
import datetime
import smtplib
def smtp():
    host="`hostname -f`"
    to = 'root@[127.0.0.1]'
    mail_user = 'postmaster@%s' % (host)
    smtpserver = smtplib.SMTP("127.0.0.1",25)
    smtpserver.ehlo()
    smtpserver.ehlo
    header = 'To:' + to + '\\n' + 'From: ' + mail_user + '\\n' + 'Subject: %s has been booted' % (host)
    print str(datetime.datetime.utcnow())[:19],host,"has been booted"
    msg = header + '\\n\\n'
    smtpserver.sendmail(mail_user, to, msg)
    smtpserver.close()
    return
smtp()
END
    if [ -z "`grep 'python /usr/local/bin/bootmail.py' /etc/rc.local`" ]; then
        sed -i "s/nothing./nothing.\\n\/usr\/bin\/python \/usr\/local\/bin\/bootmail.py/" /etc/rc.local
        print_info "bootmail.py inserted into /etc/rc.local"
    else
	    print_warn "bootmail.py already in /etc/rc.local"
    fi
}

########################################################################
# START OF PROGRAM
########################################################################
if [ "$1" = "system" -o "$1" = "all" -o "$1" = "postfix" -o "$1" = "iptables" -o "$1" = "mysql" -o "$1" = "percona" -o "$1" = "nginx" -o "$1" = "nginx-upstream" -o "$1" = "php" -o "$1" = "cgi" -o "$1" = "domain" -o "$1" = "wordpress" -o "$1" = "friendica" -o "$1" = "red" -o "$1" = "custom" -o "$1" = "upgrade" ]; then
	echo option found
else
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available options:'
    for option in system 'all' postfix iptables mysql 'percona - install mysql first' nginx 'nginx-upstream - not required unless upgrading nginx installed with an older version of this script' php cgi 'domain example.com' 'wordpress example.com' 'friendica example.com' 'red example.com' 'custom - my personal preferences' upgrade
    do
        echo '  -' $option
    done
    exit 1
fi
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
if [ ! -f ./setup-debian.conf ]; then
    cat > ./setup-debian.conf <<END
SSH_PORT=1234 # Change 1234 to the port of your choice
INTERFACE=all # Options are all for a dual stack ipv4/ipv6 server
#                           ipv4 for an ipv4 server
#                           ipv6 for an ipv6 server
#               Defaults to ipv4 only if incorrect
USER=changeme
EMAIL=\$USER@[127.0.0.1] # mail user or an external email address
OPENVZ=yes # Values are yes, no or gnome
DISTRIBUTION=wheezy # Does not do anything yet, left in for jessie
SERVER=nginx # Deprcated, now unused
CPUCORES=detect # Options are detect or n where n = number of cpu cores to be used
MEMORY=128 # values are low, 64, 96, 128, 192, 256, 384, 512, 1024, 2048 - use 2048 if more memory is available
END
fi

if [ -z "`grep 'USER=' ./setup-debian.conf`" ]; then
	sed -i "s/EMAIL=/USER=changeme\\nEMAIL=/" ./setup-debian.conf
fi
if [ -z "`grep 'CPUCORES=' ./setup-debian.conf`" ]; then
    echo CPUCORES=detect \# Options are detect or n where n = number of cpu cores to be used >> ./setup-debian.conf
fi
if [ -z "`grep 'MEMORY=' ./setup-debian.conf`" ]; then
	echo MEMORY=128 \# values are low, 64, 96, 128, 192, 256, 384, 512, 1024, 2048 - use 2048 if more memory is available >> ./setup-debian.conf
fi
if [ -z "`grep 'DISTRIBUTION=' ./setup-debian.conf`" ]; then
    echo DISTRIBUTION=wheezy \# Value is wheezy >> ./setup-debian.conf
fi
if [ -z "`grep 'SERVER=' ./setup-debian.conf`" ]; then
    echo SERVER=nginx \# Values is nginx >> ./setup-debian.conf
fi
if [ -z "`which "$1" 2>/dev/null`" -a ! "$1" = "domain" -a ! "$1" = "nginx" -a ! "$1" = "nginx-upstream" -a ! "$1" = "percona" ]; then
    apt-get -q -y update
    check_install nano "nano"
fi
if [ ! "$1" = "domain" ]; then
	nano ./setup-debian.conf
fi
[ -r ./setup-debian.conf ] && . ./setup-debian.conf

if [ "$CPUCORES" = "detect" ]; then
	CPUCORES=`grep -c processor //proc/cpuinfo`
fi

if [ "$INTERFACE" = "all" -o "$INTERFACE" = "ipv6" ]; then
    FLAGS=ipv6
else
    FLAGS=ipv4
fi

if [ "$USER" = "changeme" ]; then
	die "User changeme is not allowed"
fi
case "$1" in
all)
    remove_unneeded
    update_upgrade
    install_postfix
    install_percona
    install_nginx
    install_php
#    install_cgi
#    install_iptables $SSH_PORT
    ;;
postfix)
    add_user
    install_postfix
    ;;
iptables)
    install_iptables $SSH_PORT
    ;;
percona)
    install_percona
    ;;
nginx)
    install_nginx
    ;;
nginx-upstream)
    if [ -z "`which "nginx" 2>/dev/null`" ]; then
        print_warn "Nginx has to be installed as this is an upgrade only."
    else
        install_nginx-upstream
    fi
    ;;
php)
    install_php
    ;;
cgi)
    install_cgi
    ;;
domain)
    install_domain $1 $2 $3
    ;;
system)
    remove_unneeded
    update_upgrade
    ;;
custom)
    custom $2
    ;;
wordpress)
    install_wordpress $2
    ;;
friendica)
    install_friendica $1 $2 $3
    ;;
red)
    install_red $1 $2 $3
    ;;
upgrade)
    check_upgrade php5-fpm "php5-mysqlnd"
    if [ -e /etc/postfix/main.cf ]; then
		postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
		service postfix restart
	fi
    if [ -e /etc/php5/conf.d/lowendscript.ini ]; then
		rm -f /etc/php5/conf.d/lowendscript.ini
    fi
	if [ -e /etc/php5/mods-available/apc.ini ]; then
		apt-get install php5-xcache
	fi
    ;;
*)
    echo 'Option not found'
    ;;
esac
