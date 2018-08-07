// imports to use middleware and libraries
require('dotenv').config();
const fs = require('fs');
const bodyParser = require('body-parser');
const express = require('express');
const octokit = require('@octokit/rest');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

// code
const username = 'Blast3d'; // Added my username so the program can access my gists account.

// The object you'll be interfacing with to communicate with github
const github = octokit({ // sets octokit to a var, sets it to debug mode
  debug: true
});
const server = express(); // creates var that sets up express

// Create application/x-www-form-urlencoded parser
const urlencodedParser = bodyParser.urlencoded({
  extended: false
});

// Generate an access token: https://github.com/settings/tokens
// Set it to be able to create gists
github.authenticate({
  type: 'oauth',
  token: process.env.GITHUB_TOKEN
});

// TODO:  Attempt to load the key from config.json.  If it is not found, create a new 32 byte key.
let secretKey;
try {
  const data = fs.readFileSync('./config.json'); // uses file system to read the config file
  const keyObject = JSON.parse(data); // parses json String value or object that is in string form so it can be returned
  secretKey = nacl.util.decodeBase64(keyObject.secretKey); // fixed this line to  use nacl to decode base 64 to utf8 before it was just using the secre
} catch (err) { // catches possible error then 
  //deleted redundant code
  fs.writeFile('./config.json', JSON.stringify(keyObject), (error) => {
    if (error) {
      return error;
    }
  });
}

server.get('/', (req, res) => {
  // Return a response that documents the other routes/operations available
  res.send(`
    <html>
      <header><title>Secret Gists!</title></header>
      <body>
        <h1>Secret Gists!</h1>
        <div>This is an educational implementation.  Do not use for truly valuable information</div>
        <h2>Supported operations:</h2>
        <ul>
          <li><i><a href="/keyPairGen">Show Keypair</a></i>: generate a keypair from your secret key.  Share your public key for other users of this app to leave encrypted gists that only you can decode with your secret key.</li>
          <li><i><a href="/gists">GET /gists</a></i>: retrieve a list of gists for the authorized user (including private gists)</li>
          <li><i><a href="/key">GET /key</a></i>: return the secret key used for encryption of secret gists</li>
        </ul>
        <h3>Set your secret key to a specific key</h3>
        <form action="/setkey:keyString" method="get">
          Key String: <input type="text" name="keyString"><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Create an *unencrypted* gist</h3>
        <form action="/create" method="post">
          Name: <input type="text" name="name"><br>
          Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Create an *encrypted* gist for yourself</h3>
        <form action="/createsecret" method="post">
          Name: <input type="text" name="name"><br>
          Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Retrieve an *encrypted* gist you posted for yourself</h3>
        <form action="/fetchmessagefromself:id" method="get">
          Gist ID: <input type="text" name="id"><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Create an *encrypted* gist for a friend to decode</h3>
        <form action="/postmessageforfriend" method="post">
          Name: <input type="text" name="name"><br>
          Friend's Public Key String: <input type="text" name="publicKeyString"><br>
          Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Retrieve an *encrypted* gist a friend has posted</h3>
        <form action="/fetchmessagefromfriend:messageString" method="get">
          String From Friend: <input type="text" name="messageString"><br>
          <input type="submit" value="Submit">
        </form>
      </body>
    </html>
  `);
});

server.get('/keyPairGen', (req, res) => {
  // TODO:  Generate a keypair from the secretKey and display both
  const keypair = nacl.box.keyPair();
  // Display both keys as strings
  res.send(`
    <html>
      <header><title>Keypair</title></header>
      <body>
        <h1>Keypair</h1>
        <div>Share your public key with anyone you want to be able to leave you secret messages.</div>
        <div>Keep your secret key safe.  You will need it to decode messages.  Protect it like a passphrase!</div>
        <br/>
        <div>Public Key: ${nacl.util.encodeBase64(keypair.publicKey)}</div>
        <div>Secret Key: ${nacl.util.encodeBase64(keypair.secretKey)}</div>
      </body>
    </html>
  `);
});

server.get('/gists', (req, res) => {
  // Retrieve a list of all gists for the currently authed user
  github.gists.getForUser({
      username
    })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
});

server.get('/key', (req, res) => {
  // TODO: Display the secret key used for encryption of secret gists
  res.send(nacl.util.encodeBase64(secretKey)); // use express and pass a string encoding utility from nacl that takes the secret key as a parameter
  console.log(nacl.util.encodeBase64(secretKey)) // console logging for testing wanna see what exactly is returned.
});

server.get('/setkey:keyString', (req, res) => {
  // TODO: Set the key to one specified by the user or display an error if invalid
  const keyString = req.query.keyString;
  try {
    // TODO:
    secretKey = nacl.util.decodeUTF8(keyString);
    const keyObject = {
      secretKey: keyString
    };
    fs.writeFile('./config.json', JSON.stringify(keyObject), (error) => {
      if (error) {
        return;
      }
    });
    res.send(`<div>Key set to new value: ${keyString}</div>`);
  } catch (err) {
    // failed
    res.send('Failed to set key.  Key string appears invalid.');
  }
});

server.get('/fetchmessagefromself:id', (req, res) => {
  // TODO:  Retrieve and decrypt the secret gist corresponding to the given ID
  const id = req.query.id;
  github.gists.get({
    id
  }).then((response) => { // we get the id for the github gist which then retrieves the data for all the variables defined below and uses nacl to encrypt them
    const gist = response.data;
    const filename = Object.keys(gist.files)[0];
    const blob = gist.files[filename].content;
    const nonce = nacl.util.decodeBase64(blob.slice(0, 32));
    const ciphertext = nacl.util.decodeBase64(blob.slice(32, blob.length));
    const plaintext = nacl.secretbox.open(ciphertext, nonce, secretKey);
    res.send(nacl.util.encodeUTF8(plaintext));
  });
});

server.post('/create', urlencodedParser, (req, res) => {
  // Create a private gist with name and content given in post request
  const {
    name,
    content
  } = req.body;
  const files = {
    [name]: {
      content
    }
  };
  github.gists.create({
      files,
      public: false
    })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
});

server.post('/createsecret', urlencodedParser, (req, res) => {
  // TODO:  Create a private and encrypted gist with given name/content
  // NOTE - we're only encrypting the content, not the filename
  // sets up the gist with pseudo random data encryption for the nonce and creates a var to store that data that is now encrypted using the secretBox fnc.and sets the gist to private instead of public.
  const {
    name,
    content
  } = req.body;
  const nonce = nacl.randomBytes(24); // sets nonce to random data of 24 bytes
  const ciphertext = nacl.secretbox(nacl.util.decodeUTF8(content), nonce, secretKey); // creates a var that encrypts decrypts using the nonce and secretkey
  const blob = nacl.util.encodeBase64(nonce) + // binary blob of data that is encoded from the content of the gist
    nacl.util.encodeBase64(ciphertext);
  console.log(nacl.util.encodeBase64(ciphertext)); // testing stuff 
  const files = {
    [name]: {
      content: blob
    }
  };
  github.gists.create({
      files,
      public: false
    })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
});

server.post('/postmessageforfriend', urlencodedParser, (req, res) => {
  // TODO:  Create a private and encrypted gist with given name/content
  // using someone else's public key that can be accessed and
  // viewed only by the person with the matching private key
  // NOTE - we're only encrypting the content, not the filename
  const keypair = nacl.box.keyPair.fromSecretKey(secretKey); // posts key pair
  const blob = nacl.util.encodeBase64(nonce) +
    nacl.util.encodeBase64(ciphertext); // uses the nacl encodebase64 method to encrypt using the nonce and cipher
  const files = { // sets the content data from the blob 
    [name]: {
      content: blob
    }
  };
  const {
    name,
    publicKeyString,
    content
  } = req.body;
  const nonce = nacl.randomBytes(24);
  const ciphertext = nacl.box(nacl.util.decodeUTF8(content), nonce,
    nacl.util.decodeBase64(publicKeyString), secretKey);
});

server.get('/fetchmessagefromfriend:messageString', urlencodedParser, (req, res) => {
  // TODO:  Retrieve and decrypt the secret gist corresponding to the given ID
  const messageString = req.query.messageString;
  const friendPublicString = messageString.slice(0, 44);
  const id = messageString.slice(44, messageString.length);

  github.gists.get({
    id
  }).then((response) => {
    const gist = response.data;
    // Assuming gist has only 1 file and/or we only care about that file
    const filename = Object.keys(gist.files)[0];
    const blob = gist.files[filename].content;
    // Assume nonce is first 24 bytes of blob, split and decrypt remainder
    // N.B. 24 byte nonce == 32 characters encoded in Base64
    const nonce = nacl.util.decodeBase64(blob.slice(0, 32));
    const ciphertext = nacl.util.decodeBase64(blob.slice(32, blob.length));
    const plaintext = nacl.box.open(ciphertext, nonce,
      nacl.util.decodeBase64(friendPublicString),
      secretKey
    );
    res.send(nacl.util.encodeUTF8(plaintext));
  });
});

/* OPTIONAL - if you want to extend functionality */
server.post('/login', (req, res) => {
  // TODO log in to GitHub, return success/failure response
  // This will replace hardcoded username from above
  // const { username, oauth_token } = req.body;
  res.json({
    success: false
  });
});

server.listen(3000);