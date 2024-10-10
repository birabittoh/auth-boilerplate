# auth-boilerplate

This web-app features:
* a working folder-based file structure,
* a basic authentication service,
* a basic SMTP implementation,
* a Dockerfile for convenience,
* a GitHub workflow to create packages.


## Environment

All environment variables are optional, but some features might be disabled depending on what you have set.

* `APP_PORT`: defaults to `3000`.
* `APP_BASE_URL`: defaults to `http://localhost:<port>`.
* `APP_PEPPER`: random string, used for password hashing.
* `APP_REGISTRATION_ENABLED`: defaults to `true`.
* `APP_SMTP_EMAIL`: email address you want to send mails from.
* `APP_SMTP_PASSWORD`: password for said email address.
* `APP_SMTP_HOST`: host for the SMTP server.
* `APP_SMTP_PORT`: port for the SMTP server.

This application also looks for a `.env` file in the current directory.


## License

auth-boilerplate is licensed under MIT.
