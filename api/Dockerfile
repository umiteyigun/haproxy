FROM node:18-alpine

# Install Certbot and dependencies
RUN apk add --no-cache \
        certbot \
        python3 \
        py3-pip \
        bash \
        curl \
        expect \
        openssl

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 3000

CMD ["npm", "start"]

