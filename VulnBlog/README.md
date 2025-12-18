# Intended Vulnerable Blog

> [!CAUTION]
> This application is intended to be vulnerable. Do not deploy it in a public environment.

This project is a vulnerable application intended to be used for security training purposes.

## Deployment

### Build the Docker image manually

```bash
docker build -t vulnblog .
docker run -d --name vulnblog -p 8000:80 vulnblog
```

The application will be available at [http://localhost:8000](http://localhost:8000).
