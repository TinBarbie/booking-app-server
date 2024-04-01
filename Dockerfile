FROM node:18-alpine3.17

WORKDIR /usr/src/app

COPY package.json .

RUN npm install

COPY . ./

EXPOSE 8080:8000

ENTRYPOINT ["node", "index.js"]
