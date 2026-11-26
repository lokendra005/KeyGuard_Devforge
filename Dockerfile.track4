FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57
WORKDIR /app
COPY track4 /app/track4
COPY track4_service.cjs threat-model.json /app/
USER node
CMD ["node", "track4_service.cjs"]
