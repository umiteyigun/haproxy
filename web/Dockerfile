FROM busybox:latest
RUN mkdir -p /var/www/html
COPY . /var/www/html
EXPOSE 80
CMD ["httpd", "-f", "-v", "-p", "80", "-h", "/var/www/html"]
