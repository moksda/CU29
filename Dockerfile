FROM node:20-alpine
WORKDIR /app
COPY . .
RUN cd backend && npm install --omit=dev
EXPOSE 3001
CMD ["sh", "-c", "cd backend && node server.js"]
