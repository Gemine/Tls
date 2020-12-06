const express = require('express');
const https = require('https');
const fs = require('fs');
const port = 4443;

var key = fs.readFileSync('./certs/ca-key.pem');
var cert = fs.readFileSync('./certs/ca-cert.pem');
var options = {
  key: key,
  cert: cert
};

app = express()
app.use(
  express.urlencoded({
    extended: true
  })
)
app.post('/data', (req, res) => {
  console.log(req.body)
  res.send('Now using https..');
});

var server = https.createServer(options, app);

server.listen(port, () => {
  console.log("server starting on port : " + port)
});
