/* eslint-disable no-console */

require('dotenv').config();
const fs = require('fs');
const bodyParser = require('body-parser');
const express = require('express');
const octokit = require('@octokit/rest');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

const username = 'wvandolah'; // TODO: Replace with your username
// The object you'll be interfacing with to communicate with github
const github = octokit({ debug: true });
const server = express();

// Create application/x-www-form-urlencoded parser
const urlencodedParser = bodyParser.urlencoded({ extended: false });

// Generate an access token: https://github.com/settings/tokens
// Set it to be able to create gists
github.authenticate({
  type: 'oauth',
  token: process.env.GITHUB_TOKEN
});

// TODO:  Attempt to load the key from config.json.  If it is not found, create a new 32 byte key.

let secretKey;
try {
  const data = fs.readFileSync('./config.json');
  const keyObject = JSON.parse(data);
  secretKey = nacl.util.decodeBase64(keyObject.secretKey);
} catch (err) {
  secretKey = nacl.randomBytes(32);
  const keyObject = { secretKey: nacl.util.encodeBase64(secretKey) };
  fs.writeFile('./config.json', JSON.stringify(keyObject), (ferr) => {
    if (ferr) {
      // console.log('Error writing secret key to confing file: ', ferr.message)
      return;
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
  const keypair = nacl.box.keyPair.fromSecretKey(secretKey);
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
  github.gists.getForUser({ username })
    .then((response) => {
      res.json(response.data);
    })
    .catch((err) => {
      res.json(err);
    });
});

server.get('/key', (req, res) => {
  // TODO: Display the secret key used for encryption of secret gists
  res.send(nacl.util.encodeBase64(secretKey));
});

server.get('/setkey:keyString', (req, res) => {
  // TODO: Set the key to one specified by the user or display an error if invalid
  const keyString = req.query.keyString;
  try {
    // TODO:
    secretKey = nacl.util.decodeBase64(keyString);
    res.send(`<div>Key set to new value: ${keyString}</div>`);
    fs.writeFile('./config.json', JSON.stringify(keyString), (ferr) => {
      if (ferr) {
        // console.log('Error writing secret key to confing file: ', ferr.message)
        return;
      }
    });
  } catch (err) {
    // failed
    res.send('Failed to set key.  Key string appears invalid.');
  }
});

server.get('/fetchmessagefromself:id', (req, res) => {
  // TODO:  Retrieve and decrypt the secret gist corresponding to the given ID
  const gistId = req.query.id;
  // console.log(gist_id)
  github.gists.get({ id: gistId })
    .then((response) => {
      const encrpyedGist = response.data.files[Object.keys(response.data.files)[0]];
      // it seems that randomBytes(24) when encodeBase64 takes up 32 characters.
      const encodedNonce = encrpyedGist.content.slice(0, 32);
      const encodedContent = encrpyedGist.content.slice(32, encrpyedGist.content.length);
      const openedBox = nacl.secretbox.open(nacl.util.decodeBase64(encodedContent), nacl.util.decodeBase64(encodedNonce), secretKey);
      // console.log(openedBox);
      res.json({ title: encrpyedGist.filename, content: nacl.util.encodeUTF8(openedBox) });
    })
    .catch((err) => {
      // console.log(err);
      res.json(err);
    });
});

server.post('/create', urlencodedParser, (req, res) => {
  // Create a private gist with name and content given in post request
  const { name, content } = req.body;
  const files = { [name]: { content } };
  github.gists.create({ files, public: false })
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
  const { name, content } = req.body;
  const nonce = nacl.randomBytes(24);
  const contentUTF8 = nacl.util.decodeUTF8(content);
  const encrpyedGist = nacl.secretbox(contentUTF8, nonce, secretKey);
  const blob = nacl.util.encodeBase64(nonce) + nacl.util.encodeBase64(encrpyedGist);

  const files = { [name]: { content: blob } };
  // console.log('nonce',name)
  // console.log('contentUTF8',contentUTF8)
  // console.log('encrpyedGist',encrpyedGist)
  // console.log(files)

  github.gists.create({ files, public: false })
    .then((response) => {
      // console.log(response.data)
      // this isnt working
      res.json(response.data.files[name].content);
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
  // { name: 'test encrypt',
  // publicKeyString: 'test',
  // content: 'test' }
  const { name, publicKeyString, content } = req.body;
  // my public key needs to give in order to decode
  const myPublic = nacl.util.encodeBase64(nacl.box.keyPair.fromSecretKey(secretKey).publicKey);

  // stuff being put in blob
  const nonce = nacl.randomBytes(24);
  const contentUTF8 = nacl.util.decodeUTF8(content);
  const theirPublic = nacl.util.decodeBase64(publicKeyString);

  // using box needs nacl.box(message, nonce, theirPublicKey, mySecretKey)
  const encrpyedGist = nacl.box(contentUTF8, nonce, theirPublic, secretKey);
  const blob = nacl.util.encodeBase64(nonce) + nacl.util.encodeBase64(encrpyedGist);
  const files = { [name]: { content: blob } };
  // console.log(files)
  github.gists.create({ files, public: true })
    .then((response) => {
      // console.log(response.data.id);
      res.json(myPublic + response.data.id);
    })
    .catch((err) => {
      res.json(err);
    });
});

server.get('/fetchmessagefromfriend:messageString', urlencodedParser, (req, res) => {
  // TODO:  Retrieve and decrypt the secret gist corresponding to the given ID
  const friendString = req.query.messageString;
  const theirPublic = friendString.slice(0, 44);
  const gistId = friendString.slice(44, friendString.length);

  github.gists.get({ id: gistId })
    .then((response) => {
      const encrpyedGist = response.data.files[Object.keys(response.data.files)[0]];
      // console.log(encrpyedGist);
      // it seems that randomBytes(24) when encodeBase64 takes up 32 characters.
      const encodedNonce = encrpyedGist.content.slice(0, 32);
      const encodedContent = encrpyedGist.content.slice(32, encrpyedGist.content.length);
      // nacl.box.open(box, nonce, theirPublicKey, mySecretKey)
      const openedBox = nacl.box.open(nacl.util.decodeBase64(encodedContent), nacl.util.decodeBase64(encodedNonce),
                                                                    nacl.util.decodeBase64(theirPublic), secretKey);
      // console.log('encoded_content',encoded_content);
      // console.log('encoded_nonce',encoded_nonce);
      // console.log('theirPublic',theirPublic);
      // console.log('secretKey',secretKey);
      // console.log('opened_box', opened_box);
      res.json({ title: encrpyedGist.filename, content: nacl.util.encodeUTF8(openedBox) });
    })
    .catch((err) => {
      // console.log(err);
      res.json(err);
    });
});

/* OPTIONAL - if you want to extend functionality */
server.post('/login', (req, res) => {
  // TODO log in to GitHub, return success/failure response
  // This will replace hardcoded username from above
  // const { username, oauth_token } = req.body;
  res.json({ success: false });
});

/*
  Still want to write code? Some possibilities:
  - Pretty templates! More forms!
  - Better management of gist IDs, use/display other gist fields
  - Support editing/deleting existing gists
  - Switch from symmetric to asymmetric crypto
  - Exchange keys, encrypt messages for each other, share them
  - Let the user pass in their private key via POST
*/


server.listen(3000, () => console.log('listening on port 3000'));
