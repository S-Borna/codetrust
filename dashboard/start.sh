#!/bin/sh
# Copyright (c) Said Borna. All rights reserved.
# Startup script: run Prisma migrations then start Next.js server

echo "Generating Prisma client..."
node ./node_modules/prisma/build/index.js generate --schema=./prisma/schema.prisma 2>&1 || echo "Prisma generate warning - continuing startup..."

echo "Starting Next.js server..."
exec node server.js
