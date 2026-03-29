#!/bin/sh
# Copyright (c) Said Borna. All rights reserved.
# Startup script: run Prisma migrations then start Next.js server

echo "Starting Next.js server..."
exec node server.js
