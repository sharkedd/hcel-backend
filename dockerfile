FROM node:20 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install   # <--- instala TODAS las dependencias
COPY . .
