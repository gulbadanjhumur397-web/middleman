FROM node:20-slim

WORKDIR /app

# Install openssl for Prisma, and build tools for native node modules (usb/node-gyp/node-hid)
RUN apt-get update && apt-get install -y openssl python3 make g++ libusb-1.0-0-dev libudev-dev pkg-config && rm -rf /var/lib/apt/lists/*

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
