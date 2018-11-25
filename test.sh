#!/bin/bash
            set -e 
            set -o pipefail
            # install latest NGINX-common
            sudo apt-get update
            sudo apt-get install nginx-common -y
            # Clone nginx binary
            sudo apt-get install -y git
            git clone https://github.com/UnsightedLight/nginx-dav-public.git
            sudo cp nginx-dav-public/nginx /usr/sbin/nginx
            chmod 775 /usr/sbin/nginx
            # Start NGINX
            service nginx restart

