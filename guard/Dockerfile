FROM python:3.11-alpine
RUN apk add --no-cache iptables
WORKDIR /app
COPY guard.py .
CMD ["python", "-u", "guard.py"]
