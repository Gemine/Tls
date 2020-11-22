const express = require('express');
const https = require('https');
const fs = require('fs');
const port = 4443;

var key = fs.readFileSync('./self_sign_ca/key.pem');
var cert = fs.readFileSync('./self_sign_ca/cert.pem');
var options = {
  key: key,
  cert: cert
};

app = express()
app.get('/', (req, res) => {
   res.send('Now using https..');
});

var server = https.createServer(options, app);

server.listen(port, () => {
  console.log("server starting on port : " + port)
});
