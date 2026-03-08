#!/bin/sh
# Copyright (c) Said Borna. All rights reserved.
# Startup script: run Prisma migrations then start Next.js server

echo "Running Prisma db push..."
node ./node_modules/prisma/build/index.js db push --schema=./prisma/schema.prisma 2>&1 || echo "Prisma db push warning - continuing startup..."

echo "Starting Next.js server..."
exec node server.js
