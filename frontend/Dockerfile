FROM node:22-alpine AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./

ARG VITE_SCOPELENS_API_URL=http://127.0.0.1:8000
ENV VITE_SCOPELENS_API_URL=${VITE_SCOPELENS_API_URL}
RUN npm run build

FROM frontend-build AS demo-build
RUN npm run build:demo && npm run verify:demo

FROM python:3.14-alpine AS dashboard
WORKDIR /srv
COPY --from=frontend-build --chown=10001:10001 /frontend/dist/ /srv/
USER 10001:10001
CMD ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/srv"]

FROM python:3.14-alpine AS public-demo
WORKDIR /srv
COPY --from=demo-build --chown=10001:10001 /frontend/dist-demo/ /srv/
USER 10001:10001
CMD ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/srv"]
