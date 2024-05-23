cat <<start_content
########################################################################
#                                                                      #
#               LibreTime Installation and Hardening Script            #
#                                                                      #
#                  Created by Honeytree Technologies, LLC              #
#                            www.honeytreetech.com                     #
#                                                                      #
#                     LibreTime : honeytree.social                     #
#                      Email : info@honeytreetech.com                  #
#                                                                      #
########################################################################
start_content

sleep 3

cat <<startup_warning
########################################################################
#####  THIS IS IMPORTANT, PLEASE READ CAREFULLY BEFORE SELECTING   #####
#####                                                              #####
#####   This will install LibreTime on fresh server                #####
#####                                                              #####
#####  Installing on an operating LibreTime server will wipe data  #####
#####                                                              #####
########################################################################
startup_warning


# Function to generate a random character
function random_char() {
  local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  echo -n "${chars:RANDOM%${#chars}:1}"
}

# Function to generate a random string of a given length
function random_string() {
  local length=$1
  local result=""
  for ((i = 0; i < length; i++)); do
    result="${result}$(random_char)"
  done
  echo -n "$result"
}

# Function to validate if the port number is within the specified range
validate_port() {
    local port=$1
    local excluded_ports=("80" "443" "3000")

    if [[ $port =~ ^[0-9]+$ && $port -ge 0 && $port -le 65536 ]]; then
        for excluded_port in "${excluded_ports[@]}"; do
            if [ "$port" -eq "$excluded_port" ]; then
                return 2  # Excluded port
            fi
        done
        return 0  # Valid port number
    else
        return 1  # Invalid port number
    fi
}


while true; do
  read -p "Enter valid domain name: " domain_name
  if [ -n "${domain_name}" ]; then
    break
  else
    echo "Domain cannot be empty. Please enter domain."
  fi
done

read -p "Enter the DB USER NAME (Default: libretime): " db_username
if [ -z ${db_username} ] ; then
  db_username=libretime
fi

temp_db_password="pass_$(random_string 16)"
read -p "Enter the DB PASSWORD (Default: ${temp_db_password}): " db_password
if [ -z ${db_password} ] ; then
  db_password=${temp_db_password}
fi
echo "Your db password is ${db_password}"


temp_db="libre_$(random_string 8)"
read -p "Enter the DB NAME (Default: ${temp_db}): " db_name
if [ -z ${db_name} ] ; then
  db_name=${temp_db}
fi
echo "Your db name is ${db_name}"



while true; do
  read -p "Enter SMTP HOST: " smtp_host
  if [ -n "$smtp_host" ]; then
    break
  else
    echo "SMTP HOST cannot be empty. Please enter smtp host."
  fi
done

while true; do
  read -p "Enter SMTP PORT: " smtp_port
  if [ -n "$smtp_port" ]; then

    break
  else
    echo "SMTP PORT cannot be empty. Please enter smtp port."
  fi
done

while true; do
  read -p "Enter SMTP USER: " smtp_user
  if [ -n "$smtp_user" ]; then
    break
  else
    echo "SMTP USER cannot be empty. Please enter smtp_user."
  fi
done

while true; do
  read -p "Enter SMTP_PASSWORD: " smtp_password
  if [ -n "$smtp_password" ]; then
    break
  else
    echo "SMTP_PASSWORD cannot be empty. Please enter smtp password."
  fi
done

while true; do
  read -p "Enter SMTP FROM ADDRESS: " smtp_from_address
  if [ -n "$smtp_from_address" ]; then
    break
  else
    echo "SMTP FROM ADDRESS cannot be empty. Please enter smtp from address."
  fi
done

while true; do
  read -p "Enter SMTP encryption (ssl/tls or starttls): " smtp_encryption
  if [[ "${smtp_encryption}" == "ssl/tls" || "${smtp_encryption}" == "starttls" ]]; then
    break
  else
    echo "Invalid input. Please enter 'ssl/tls' or 'starttls'."
  fi
done


temp_ruser="rabbitmq_$(random_string 8)"
read -p "Enter the RabbitMQ user name (Default: ${temp_ruser}): " ruser
if [ -z ${ruser} ] ; then
  ruser=${temp_ruser}
fi
echo "Your RabbitMQ user name is ${ruser}"

temp_rpassword="rabbitmq_$(random_string 8)"
read -p "Enter the RabbitMQ password (Default: ${temp_rpassword}): " rpassword
if [ -z ${rpassword} ] ; then
  rpassword=${temp_rpassword}
fi
echo "Your RabbitMQ password is ${rpassword}"

temp_i_s_user="i_s_$(random_string 8)"
read -p "Enter the Icecast source user name (Default: ${temp_i_s_user}): " ice_source_user
if [ -z ${ice_source_user} ] ; then
  ice_source_user=${temp_i_s_user}
fi
echo "Your Icecast source user name is ${ice_source_user}"

temp_i_s_password="i_s_$(random_string 8)"
read -p "Enter the Icecast source password (Default: ${temp_i_s_password}): " ice_source_password
if [ -z ${ice_source_password} ] ; then
  ice_source_password=${temp_i_s_password}
fi
echo "Your Icecast source password is ${ice_source_password}"

temp_i_a_password="i_a_$(random_string 8)"
read -p "Enter the Icecast admin user name (Default: ${temp_i_a_password}): " ice_admin_user
if [ -z ${ice_admin_user} ] ; then
  ice_admin_user=${temp_i_a_password}
fi
echo "Your Icecast admin user name is ${ice_source_user}"

temp_i_a_password="i_a_$(random_string 8)"
read -p "Enter the Icecast admin password (Default: ${temp_i_a_password}): " ice_admin_password
if [ -z ${ice_admin_password} ] ; then
  ice_admin_password=${temp_i_a_password}
fi
echo "Your Icecast admin password is ${ice_admin_password}"

while true; do
  read -p "Enter a ssh_port number (1-65535, excluding 80, 443, and 3000): " port
  # Validate the input
  validate_port "$port"
  case $? in
    0)
      echo "SSH  port will be: $port"
      ssh_port=$port
      break  # Exit the loop as a valid port has been entered
      ;;
    1)
      echo "Invalid port number. Please enter a valid port number between 1 and 65535."
      ;;
    2)
      echo "Invalid port number. Port $port is excluded. Please choose a different port."
      ;;
  esac
done

# Remove old docker container if docker already present 
if docker -v &>/dev/null; then
  sudo docker rm -f $(docker ps -a -q)
  sudo docker volume rm $(docker volume ls)
fi

# install new version of docker
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release
if test -f /usr/share/keyrings/docker-archive-keyring.gpg; then
 sudo rm /usr/share/keyrings/docker-archive-keyring.gpg
fi
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y  docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose

work_dir=~/libreTime
sudo rm -rf ${work_dir}
mkdir ${work_dir}

cat<<nginx_conf >${work_dir}/nginx.conf
server {
  listen 8080;
  listen [::]:8080;

  root /var/www/html/public;

  index index.php index.html index.htm;

  client_max_body_size 512M;
  client_body_timeout 300s;

  location ~ \.php$ {
    fastcgi_buffers 64 4K;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;

    #try_files \$uri =404;
    try_files \$fastcgi_script_name =404;

    include fastcgi_params;

    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    set \$path_info \$fastcgi_path_info;
    fastcgi_param PATH_INFO \$path_info;
    include fastcgi_params;

    fastcgi_index index.php;
    fastcgi_pass legacy:9000;
  }

  location / {
    try_files \$uri \$uri/ /index.php\$is_args\$args;

  }

  location ~ ^/api/(v2|browser) {
    proxy_set_header Host \$http_host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;

    proxy_redirect off;
    proxy_pass http://api:9001;
  }

  # Internal path for serving media files from the API.
  location /api/_media {
    internal;
    # This alias path must match the 'storage.path' configuration field.
    alias /srv/libretime;
  }
}
nginx_conf

cat <<environmental_variable >${work_dir}/config.yml
# See https://libretime.org/docs/admin-manual/setup/configuration/

general:
  # The public url.
  # > this field is REQUIRED
  public_url: 'https://${domain_name}'
  # The internal API authentication key.
  # > this field is REQUIRED
  api_key: `openssl rand -base64 12`
  # The Django API secret key.
  # > this field is REQUIRED
  secret_key: `openssl rand -base64 12`

  # List of origins allowed to access resources on the server, the public url
  # origin is automatically included.
  # > default is []
  allowed_cors_origins: []

  # The server timezone, should be a lookup key in the IANA time zone database,
  # for example Europe/Berlin.
  # > default is UTC
  timezone: UTC

  # How many hours ahead Playout should cache scheduled media files.
  # > default is 1
  cache_ahead_hours: 1

  # Authentication adaptor to use for the legacy service, specify a class like
  # LibreTime_Auth_Adaptor_FreeIpa to replace the built-in adaptor.
  # > default is local
  auth: local

storage:
  # Path of the storage directory. Make sure to update the Nginx configuration after
  # updating the storage path.
  # > default is /srv/libretime
  path: /srv/libretime

database:
  # The hostname of the PostgreSQL server.
  # > default is localhost
  host: postgres
  # The port of the PostgreSQL server.
  # > default is 5432
  port: 5432
  # The name of the PostgreSQL database.
  # > default is libretime
  name: ${db_name}
  # The username of the PostgreSQL user.
  # > default is libretime
  user: ${db_username}
  # The password of the PostgreSQL user.
  # > default is libretime
  password: ${db_password} 

rabbitmq:
  # The hostname of the RabbitMQ server.
  # > default is localhost
  host: rabbitmq
  # The port of the RabbitMQ server.
  # > default is 5672
  port: 5672
  # The virtual host of RabbitMQ server.
  # > default is /libretime
  vhost: /libretime
  # The username of the RabbitMQ user.
  # > default is libretime
  user: ${ruser}
  # The password of the RabbitMQ user.
  # > default is libretime
  password: ${rpassword}

email:
  # Sender email address to use when sending emails.
  # > default is no-reply@libretime.org
  from_address: ${smtp_from_address}

  # The hostname of the SMTP server.
  # > default is localhost
  host: ${smtp_host}
  # The port of the SMTP server.
  # > default is 25
  port: ${smtp_port}
  # Whether to use an insecure connection, an SSL/TLS (implicit) connection (generally
  # on port 465) or a STARTTLS (explicit) connection (generally on port 587) when
  # talking to the SMTP server.
  # > must be one of (ssl/tls, starttls)
  encryption: ${smtp_encryption}
  # The username to use for the SMTP server.
  # > default is ""
  user: ${smtp_user}
  # The password to use for the SMTP server.
  # > default is ""
  password: ${smtp_password}
  # Timeout in seconds for blocking operations like the connection attempt.
  timeout: 10
  # The path to a PEM-formatted certificate chain file to use for the connection.
  cert_file:
  # The path to a PEM-formatted private key file to use for the connection.
  key_file:

playout:
  # Liquidsoap connection host.
  # > default is localhost
  liquidsoap_host: liquidsoap
  # Liquidsoap connection port.
  # > default is 1234
  liquidsoap_port: 1234

  # The format for recordings.
  # > must be one of (ogg, mp3)
  # > default is ogg
  record_file_format: ogg
  # The bitrate for recordings.
  # > default is 256
  record_bitrate: 256
  # The samplerate for recordings.
  # > default is 44100
  record_samplerate: 44100
  # The number of channels for recordings.
  # > default is 2
  record_channels: 2
  # The sample size for recordings.
  # > default is 16
  record_sample_size: 16

liquidsoap:
  # Liquidsoap server listen address.
  # > default is 127.0.0.1
  server_listen_address: 0.0.0.0
  # Liquidsoap server listen port.
  # > default is 1234
  server_listen_port: 1234

  # Input harbor listen address.
  # > default is ["0.0.0.0"]
  harbor_listen_address: ["0.0.0.0"]

  # Input harbor tls certificate path.
  harbor_ssl_certificate:
  # Input harbor tls certificate private key path.
  harbor_ssl_private_key:
  # Input harbor tls certificate password.
  harbor_ssl_password:

stream:
  # Inputs sources.
  inputs:
    # Main harbor input.
    main:
      # Harbor input public url. If not defined, the value will be generated from
      # the [general.public_url] hostname, the input port and mount.
      public_url:
      # Mount point for the main harbor input.
      # > default is main
      mount: main
      # Listen port for the main harbor input.
      # > default is 8001
      port: 8001
      # Whether the input harbor is secured with the tls certificate.
      # > default is false
      secure: false

    # Show harbor input.
    show:
      # Harbor input public url. If not defined, the value will be generated from
      # the [general.public_url] hostname, the input port and mount.
      public_url:
      # Mount point for the show harbor input.
      # > default is show
      mount: show
      # Listen port for the show harbor input.
      # > default is 8002
      port: 8002
      # Whether the input harbor is secured with the tls certificate.
      # > default is false
      secure: false

  # Output streams.
  outputs:
    # Default icecast output
    # This can be reused to define multiple outputs without duplicating data
    .default_icecast_output: &default_icecast_output
      host: icecast
      port: 8000
      source_password: ${ice_source_user}
      admin_password: ${ice_admin_password}
      name: LibreTime!
      description: LibreTime Radio!
      website: https://libretime.org
      genre: various

    # Icecast output streams.
    # > max items is 3
    icecast:
      # The default Icecast output stream
      - <<: *default_icecast_output
        enabled: true
        public_url:
        mount: main
        audio:
          format: ogg
          bitrate: 256

      # You can define extra outputs by reusing the default output using a yaml anchor
      - <<: *default_icecast_output
        enabled: false
        mount: main-low
        audio:
          format: ogg
          bitrate: 128

      - # Whether the output is enabled.
        # > default is false
        enabled: false
        # Output public url, If not defined, the value will be generated from
        # the [general.public_url] hostname, the output port and mount.
        public_url:
        # Icecast server host.
        # > default is localhost
        host: localhost
        # Icecast server port.
        # > default is 8000
        port: 8000
        # Icecast server mount point.
        # > this field is REQUIRED
        mount: main
        # Icecast source user.
        # > default is source
        source_user: ${ice_source_user}
        # Icecast source password.
        # > this field is REQUIRED
        source_password: ${ice_source_password}
        # Icecast admin user.
        # > default is admin
        admin_user: ${ice_admin_user}
        # Icecast admin password. If not defined, statistics will not be collected.
        admin_password: ${ice_admin_password}

        # Icecast output audio.
        audio:
          # Icecast output audio format.
          # > must be one of (aac, mp3, ogg, opus)
          # > this field is REQUIRED
          format: ogg
          # Icecast output audio bitrate.
          # > must be one of (32, 48, 64, 96, 128, 160, 192, 224, 256, 320)
          # > this field is REQUIRED
          bitrate: 256

          # format=ogg only field: Embed metadata (track title, artist, and show name)
          # in the output stream. Some bugged players will disconnect from the stream
          # after every songs when playing ogg streams that have metadata information
          # enabled.
          # > default is false
          enable_metadata: false

        # Icecast stream name.
        name: LibreTime!
        # Icecast stream description.
        description: LibreTime Radio!
        # Icecast stream website.
        website: https://libretime.org
        # Icecast stream genre.
        genre: various

        # Whether the stream should be used for mobile devices.
        # > default is false
        mobile: false

    # Shoutcast output streams.
    # > max items is 1
    shoutcast:
      - # Whether the output is enabled.
        # > default is false
        enabled: false
        # Output public url. If not defined, the value will be generated from
        # the [general.public_url] hostname and the output port.
        public_url:
        # Shoutcast server host.
        # > default is localhost
        host: localhost
        # Shoutcast server port.
        # > default is 8000
        port: 8000
        # Shoutcast source user.
        # > default is source
        source_user: ${ice_source_user}
        # Shoutcast source password.
        # > this field is REQUIRED
        source_password: ${ice_source_password}
        # Shoutcast admin user.
        # > default is admin
        admin_user: ${ice_admin_user}
        # Shoutcast admin password. If not defined, statistics will not be collected.
        admin_password: ${ice_admin_password}

        # Shoutcast output audio.
        audio:
          # Shoutcast output audio format.
          # > must be one of (aac, mp3)
          # > this field is REQUIRED
          format: mp3
          # Shoutcast output audio bitrate.
          # > must be one of (32, 48, 64, 96, 128, 160, 192, 224, 256, 320)
          # > this field is REQUIRED
          bitrate: 256

        # Shoutcast stream name.
        name: LibreTime!
        # Shoutcast stream website.
        website: https://libretime.org
        # Shoutcast stream genre.
        genre: various

        # Whether the stream should be used for mobile devices.
        # > default is false
        mobile: false

    # System outputs.
    # > max items is 1
    system:
      - # Whether the output is enabled.
        # > default is false
        enabled: false
        # System output kind.
        # > must be one of (alsa, ao, oss, portaudio, pulseaudio)
        # > default is pulseaudio
        kind: pulseaudio

        # System output device.
        # > only available for kind=(alsa, pulseaudio)
        device:

environmental_variable

cat<<docker_content >${work_dir}/docker-compose.yml
version: "2.2"

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: ${db_username}
      POSTGRES_PASSWORD: ${db_password} 
      POSTGRES_DB: ${db_name}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  rabbitmq:
    image: rabbitmq:3.12-alpine
    environment:
      RABBITMQ_DEFAULT_VHOST: ${RABBITMQ_DEFAULT_VHOST:-/libretime}
      RABBITMQ_DEFAULT_USER: ${ruser}
      RABBITMQ_DEFAULT_PASS: ${rpassword}
    healthcheck:
      test: rabbitmq-diagnostics -q ping

  playout:
    image: ghcr.io/libretime/libretime-playout:latest
    init: true
    ulimits:
      nofile: 1024
    depends_on:
      - rabbitmq
    volumes:
      - ${LIBRETIME_CONFIG_FILEPATH:-./config.yml}:/etc/libretime/config.yml:ro
      - libretime_playout:/app
    environment:
      LIBRETIME_GENERAL_PUBLIC_URL: http://nginx:8080

  liquidsoap:
    image: ghcr.io/libretime/libretime-playout:latest
    command: /usr/local/bin/libretime-liquidsoap
    init: true
    ulimits:
      nofile: 1024
    ports:
      - 8001:8001
      - 8002:8002
    depends_on:
      - rabbitmq
    volumes:
      - ${LIBRETIME_CONFIG_FILEPATH:-./config.yml}:/etc/libretime/config.yml:ro
      - libretime_playout:/app
    environment:
      LIBRETIME_GENERAL_PUBLIC_URL: http://nginx:8080

  analyzer:
    image: ghcr.io/libretime/libretime-analyzer:latest
    init: true
    ulimits:
      nofile: 1024
    depends_on:
      - rabbitmq
    volumes:
      - ${LIBRETIME_CONFIG_FILEPATH:-./config.yml}:/etc/libretime/config.yml:ro
      - libretime_storage:/srv/libretime
    environment:
      LIBRETIME_GENERAL_PUBLIC_URL: http://nginx:8080

  worker:
    image: ghcr.io/libretime/libretime-worker:latest
    init: true
    ulimits:
      nofile: 1024
    depends_on:
      - rabbitmq
    volumes:
      - ${LIBRETIME_CONFIG_FILEPATH:-./config.yml}:/etc/libretime/config.yml:ro
    environment:
      LIBRETIME_GENERAL_PUBLIC_URL: http://nginx:8080

  api:
    image: ghcr.io/libretime/libretime-api:latest
    init: true
    ulimits:
      nofile: 1024
    depends_on:
      - postgres
      - rabbitmq
    volumes:
      - ${LIBRETIME_CONFIG_FILEPATH:-./config.yml}:/etc/libretime/config.yml:ro
      - libretime_storage:/srv/libretime

  legacy:
    image: ghcr.io/libretime/libretime-legacy:latest
    init: true
    ulimits:
      nofile: 1024
    depends_on:
      - postgres
      - rabbitmq
    volumes:
      - ${LIBRETIME_CONFIG_FILEPATH:-./config.yml}:/etc/libretime/config.yml:ro
      - libretime_assets:/var/www/html
      - libretime_storage:/srv/libretime

  nginx:
    image: nginx
    ports:
      - 3000:8080
    depends_on:
      - legacy
    volumes:
      - libretime_assets:/var/www/html:ro
      - libretime_storage:/srv/libretime:ro
      - ${NGINX_CONFIG_FILEPATH:-./nginx.conf}:/etc/nginx/conf.d/default.conf:ro

  icecast:
    image: ghcr.io/libretime/icecast:2.4.4
    ports:
      - 8000:8000
    environment:
      ICECAST_SOURCE_PASSWORD: ${ice_source_password} # Change me !
      ICECAST_ADMIN_PASSWORD: ${ice_admin_password} # Change me !
      ICECAST_RELAY_PASSWORD: ${ICECAST_RELAY_PASSWORD:-hackme} # Change me !

volumes:
  postgres_data: {}
  libretime_storage: {}
  libretime_assets: {}
  libretime_playout: {}

docker_content

cd ${work_dir}
sudo docker rm -f $(docker ps -a -q)
sudo docker volume rm $(docker volume ls)
docker-compose  run --rm api libretime-api migrate
docker-compose  -f docker-compose.yml up -d

if nginx -v &>/dev/null; then
  echo "Nginx is already install installed"
  rm /etc/nginx/sites-available/libretime
  rm /etc/nginx/sites-enabled/libretime
else
  sudo apt-get update
  sudo apt-get install -y nginx
fi

# make the nginx file for the application 
touch /etc/nginx/sites-available/libretime
cat <<nginx_content >>/etc/nginx/sites-available/libretime
server {

    server_name ${domain_name};

    proxy_set_header Host \$host;

    proxy_set_header X-Real-IP \$remote_addr;

    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    proxy_set_header X-Forwarded-Proto \$scheme;

    proxy_set_header Proxy "";

    proxy_http_version 1.1;

    proxy_set_header Upgrade \$http_upgrade;

    proxy_set_header Connection "upgrade";



        location / {

            proxy_pass http://localhost:3000;

            proxy_pass_header Server;



            proxy_buffering on;

            proxy_redirect off;

        }

}
nginx_content

#  Link to sites-enabled to enable the virtual host.
sudo ln -s /etc/nginx/sites-available/libretime /etc/nginx/sites-enabled/

#  Reload the nginx service.
sudo systemctl restart nginx

# Config ufw firewall to allow Nginx ports. Skip if your server doesn't have ufw.
sudo ufw allow 'Nginx Full'

# Secure AzuraCast with Let's Encrypt SSL
sudo apt-get install -y certbot python3-certbot-nginx

# Generate the ssl certificate for domain
sudo certbot --nginx -d ${domain_name}

systemctl restart nginx

sudo cp /etc/ssh/ssh_config /etc/ssh/ssh_config_copy
sudo rm /etc/ssh/ssh_config

cat <<ssh_content >> /etc/ssh/ssh_config
Host *
#   ForwardAgent no
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
#   StrictHostKeyChecking ask
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
   Port ${ssh_port}
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
#   UserKnownHostsFile ~/.ssh/known_hosts.d/%k
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
ssh_content

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config_copy
sudo rm /etc/ssh/sshd_config

cat <<sshd_content >> /etc/ssh/sshd_config
PermitRootLogin yes


# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port ${ssh_port}
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem sftp  /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
# X11Forwarding no
# AllowTcpForwarding no
# PermitTTY no
# ForceCommand cvs server
sshd_content

#  restart sshd service
systemctl reload ssh
systemctl reload sshd
systemctl restart ssh
systemctl restart sshd

# set up a firewall with ufw.
sudo apt-get install ufw
sudo ufw default allow outgoing
sudo ufw default deny incoming
sudo ufw allow ${ssh_port}/tcp comment 'SSH'
sudo ufw allow http comment 'HTTP'
sudo ufw allow https comment 'HTTPS'
 yes | sudo ufw enable


sudo apt-get install -y fail2ban
rm /etc/fail2ban/jail.local
touch /etc/fail2ban/jail.local

cat << fail2ban_ban >> /etc/fail2ban/jail.local
[ssh]
enabled = true
banaction = iptables-multiport
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 43200
bantime = 86400
fail2ban_ban

sudo systemctl restart fail2ban

echo "Congratulations! Your setup is done."
echo "Database user: ${db_user}, Password: ${db_password}, and name: ${db_name}."
echo "RabbitMQ User: ${ruser}, Password: ${rpassword}"
echo "Icecast source User: ${ice_source_user}, Password: ${ice_source_password}"
echo "Icecast admin User: ${ice_admin_user}, Password: ${ice_admin_password}"
echo "The libretime instance can be accessed at https://${domain_name}."
echo "Use User: admin and Password: admin  to first time login and change password."
echo "Now SSH port is ${ssh_port}."
