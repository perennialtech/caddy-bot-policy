FROM nginx:stable-alpine
RUN apk add --no-cache openssl
COPY front.nginx.conf /etc/nginx/conf.d/default.conf

CMD openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' \
    -keyout /tmp/localhost.key -out /tmp/localhost.crt \
    >/dev/null 2>&1 && exec nginx -g 'daemon off;'
