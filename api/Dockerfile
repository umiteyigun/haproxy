FROM node:18-alpine

# Install Certbot and dependencies
RUN apk add --no-cache \
        certbot \
        python3 \
        py3-pip \
        bash \
        curl \
        expect \
        openssl \
        certbot-dns-cloudflare \
        certbot-dns-digitalocean \
        certbot-dns-route53 \
        certbot-dns-google \
        certbot-dns-ovh \
        socat

# Install acme.sh
RUN curl https://get.acme.sh | sh && \
        ln -s /root/.acme.sh/acme.sh /usr/local/bin/acme.sh

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 3000

CMD ["npm", "start"]

