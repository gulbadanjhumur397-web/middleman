FROM node:20-alpine

WORKDIR /app

# Install openssl for Prisma, and build tools for native node modules (usb/node-gyp)
RUN apk add --no-cache openssl python3 make g++ linux-headers eudev-dev

# Install dependencies
COPY package*.json ./
RUN npm ci --production=false

# Copy source
COPY . .

# Generate Prisma client (needs a dummy DATABASE_URL at build time)
RUN DATABASE_URL="postgresql://dummy:dummy@localhost:5432/dummy" npx prisma generate

EXPOSE 8080 3001

# Start with ts-node
CMD ["npx", "ts-node", "src/index.ts"]
