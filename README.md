# housework-backend
Backend for housework app.

##How to install and set up the API for an Apache web server (LAMP).
The user installing is expected to be a member of www-data group.

1. Clone the repository to your server. It's recommended to choose a directory under the web root.
In this example we will clone the repo to "/var/www"
```
cd /var/www
git clone https://github.com/tuomt/housework-backend
```
2. Create a directory for secrets:
```
sudo mkdir housework-backend/priv/secrets
```
3. Create a file in path `housework-backend/priv/secrets/db_secrets.json`
   with the content below.
   Change the values to match your database configuration.
```
{
  "hostname": "DATABASE HOSTNAME HERE, e.g. localhost",
  "database": "MYSQL DATABASE NAME HERE",
  "username": "MYSQL USERNAME HERE",
  "password": "MYSQL PASSWORD HERE"
}
```
4. Create a file in path `housework-backend/priv/secrets/jwt_secrets.json`
   with the content below.
   Create a unique string for each key. Don't use same string more than once.
```
{
  "accessTokenKey": "PRIVATE KEY FOR ACCESS TOKEN",
  "refreshTokenKey": "PRIVATE KEY FOR REFRESH TOKEN",
  "groupTokenKey": "PRIVATE KEY FOR GROUP TOKEN"
}
```
5. Set permissions for directories:
```
sudo chown -R www-data:www-data housework-backend
sudo chmod -R 774 housework-backend
sudo chown -R root:root housework-backend/priv/secrets
sudo chmod -R 700 housework-backend/priv/secrets
```
6. Install dependencies by executing the following command:
```
php composer.phar install
```
7. Add the following rewrite rules to your Apache config.
   You have to specify your Apache document root as the directory name.
   In this example our document root is /var/www/
```
<Directory "/var/www/">

   # Rewrite API requests to altorouter
   RewriteEngine on
   RewriteCond %{REQUEST_FILENAME} !-f
   RewriteCond %{REQUEST_FILENAME} !-d
   RewriteRule ^api/ /apirouter.php

</Directory>
```
8. Add an Alias for the apirouter.php in your Apache config:
```
<IfModule alias_module>
   Alias /apirouter.php /var/www/housework-backend/public/apirouter.php
</IfModule>
```
9. Add the following directory access restrictions:
```
# Deny public access to all project files
<Directory "/var/www/housework-backend/">
    AllowOverride All
    Require all denied
    Options -Indexes
</Directory>

# Grant public access to public files
<Directory "/var/www/housework-backend/public">
    AllowOverride None
    Require all granted
</Directory>
```
10. Restart the Apache web server:
```
sudo apachectl restart
```
